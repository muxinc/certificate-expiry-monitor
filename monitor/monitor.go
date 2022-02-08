package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	tlsConnectionTimeout = 5 * time.Second

	validLabel    = "valid"
	expiredLabel  = "expired"
	soonLabel     = "soon"
	notFoundLabel = "notfound"
)

// CertExpiryMonitor periodically checks certificate expiry times
type CertExpiryMonitor struct {
	Logger             *logrus.Logger
	KubernetesClient   *kubernetes.Clientset
	PollingFrequency   time.Duration
	Namespaces         []string
	Labels             string
	IngressNamespaces  []string
	Domains            []string
	IgnoredDomains     []string
	HostIP             bool
	Port               int
	InsecureSkipVerify bool
	IngressAPIVersion  string
}

func containsDomain(l []string, domain string) bool {
	for _, d := range l {
		if d == domain {
			return true
		}
		if len(d) > 2 && d[0] == '/' && d[len(d)-1] == '/' {
			// Evaluate regexes provided like: /.*\.domain\.com$/
			if regexp.MustCompile(d[1 : len(d)-1]).MatchString(domain) {
				return true
			}
		}
	}
	return false
}

// Run the monitor until instructed to stop
func (m *CertExpiryMonitor) Run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	// setup list options
	listOptions := metav1.ListOptions{
		LabelSelector: m.Labels,
	}
	coreApi := m.KubernetesClient.CoreV1()
	extApi := m.KubernetesClient.ExtensionsV1beta1()
	netApi := m.KubernetesClient.NetworkingV1()
	ticker := time.NewTicker(m.PollingFrequency)

	for {
		m.Logger.Debug("Polling")

		// discover domains from ingresses.
		var discoveredDomains []string
		for _, ns := range m.IngressNamespaces {
			var possibleDomains []string
			if ns == "" {
				break
			}
			switch m.IngressAPIVersion {
			case "extensions/v1beta1":
				il, err := extApi.Ingresses(ns).List(ctx, metav1.ListOptions{})
				if err != nil {
					m.Logger.WithField("ns", ns).Errorf("Failed to list ingresses using ExtensionsV1beta1: %v", err)
					return
				}
				for _, i := range il.Items {
					for _, ir := range i.Spec.Rules {
						possibleDomains = append(possibleDomains, ir.Host)
					}
				}
			case "networking/v1":
				il, err := netApi.Ingresses(ns).List(ctx, metav1.ListOptions{})
				if err != nil {
					m.Logger.WithField("ns", ns).Errorf("Failed to list ingresses using ExtensionsV1beta1: %v", err)
					return
				}
				for _, i := range il.Items {
					for _, ir := range i.Spec.Rules {
						possibleDomains = append(possibleDomains, ir.Host)
					}
				}
			default:
				m.Logger.WithField("ns", ns).Errorf("Invalid ingress API version provided, got %s but has to be either `extensions/v1beta1` or `networking/v1`", m.IngressAPIVersion)
				return
			}

			for _, possibleDomain := range possibleDomains {
				if containsDomain(m.IgnoredDomains, possibleDomain) {
					m.Logger.WithField("ns", ns).Debugf("ignored host: %s", possibleDomain)
				} else if !containsDomain(discoveredDomains, possibleDomain) {
					m.Logger.WithField("ns", ns).Debugf("discovered host: %s", possibleDomain)
					discoveredDomains = append(discoveredDomains, possibleDomain)
				}
			}
		}

		if len(discoveredDomains) > 0 {
			m.Domains = discoveredDomains
		}

		// iterate over namespaces to monitor
		for _, ns := range m.Namespaces {
			// list pods matching the labels in this namespace
			pods, err := coreApi.Pods(ns).List(ctx, listOptions)
			if err != nil {
				m.Logger.WithField("ns", ns).Errorf("Failed to list pods using NetworkingV1: %v", err)
				return
			}

			// iterate over matching pods in namespace
			matchingPods.WithLabelValues(ns).Set(float64(len(pods.Items)))
			m.Logger.WithField("ns", ns).Debugf("Number of matching pods found in namespace: %d", len(pods.Items))
			podsWG := &sync.WaitGroup{}
			for _, pod := range pods.Items {
				ip := pod.Status.PodIP
				if m.HostIP {
					ip = pod.Status.HostIP
				}
				go m.checkCertificates(podsWG, ns, pod.Name, ip)
			}
			podsWG.Wait()
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			m.Logger.Info("Monitor stopping")
			return
		}
	}
}

func (m *CertExpiryMonitor) checkCertificates(wg *sync.WaitGroup, namespace, pod, podIP string) {
	wg.Add(1)
	defer wg.Done()

	currentTime := time.Now()
	tlsConfig := tls.Config{InsecureSkipVerify: m.InsecureSkipVerify}

	// iterate over domains that need to be checked, setting the domain in the TLS connection config for SNI
	for _, domain := range m.Domains {
		logger := m.Logger.WithFields(logrus.Fields{"ns": namespace, "pod": pod, "domain": domain})

		// connect to the pod over TLS
		tlsConfig.ServerName = domain
		dialer := new(net.Dialer)
		dialer.Timeout = tlsConnectionTimeout
		conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", podIP, m.Port), &tlsConfig)
		if err != nil {
			tlsOpenConnectionError.WithLabelValues(namespace, pod, domain).Inc()
			logger.Errorf("Error connecting to pod to check certificates: %v", err)
			return
		}

		// iterate over certificates returned by pod, looking for matches against the domain we're verifying
		certificateStatus.WithLabelValues(namespace, pod, domain, expiredLabel).Set(0)
		certificateStatus.WithLabelValues(namespace, pod, domain, validLabel).Set(0)
		certificateStatus.WithLabelValues(namespace, pod, domain, soonLabel).Set(0)
		certificateStatus.WithLabelValues(namespace, pod, domain, notFoundLabel).Set(0)
		certFound := false
		for _, cert := range conn.ConnectionState().PeerCertificates {
			certLogger := logger.WithField("subject", cert.Subject)
			if err := cert.VerifyHostname(domain); err != nil {
				certLogger.Warnf("Certificate was not valid for domain: %v", err)
				continue
			}

			certFound = true
			certLogger.Debugf("Checking certificate: Not-Before=%v Not-After=%v", cert.NotBefore, cert.NotAfter)
			if cert.NotAfter.Before(currentTime) {
				certLogger.Warnf("Certificate has expired: Not-After=%v", cert.NotAfter)
				certificateStatus.WithLabelValues(namespace, pod, domain, expiredLabel).Set(1)
			} else if cert.NotBefore.After(currentTime) {
				certLogger.Warnf("Certificate is not yet valid: Not-Before=%v", cert.NotBefore)
				certificateStatus.WithLabelValues(namespace, pod, domain, soonLabel).Set(1)
			} else {
				certLogger.Debugf("Certificate is valid")
				certificateStatus.WithLabelValues(namespace, pod, domain, validLabel).Set(1)
			}
			certificateSecondsSinceIssued.WithLabelValues(namespace, pod, domain).Set(currentTime.Sub(cert.NotBefore).Seconds())
			certificateSecondsUntilExpires.WithLabelValues(namespace, pod, domain).Set(cert.NotAfter.Sub(currentTime).Seconds())
			break
		}

		if !certFound {
			logger.Warn("No matching certificates found for domain")
			certificateStatus.WithLabelValues(namespace, pod, domain, notFoundLabel).Set(1)
		}
		if err := conn.Close(); err != nil {
			tlsCloseConnectionError.WithLabelValues(namespace, pod, domain).Inc()
			logger.Errorf("Error closing TLS connection after checking certificates: %v", err)
		}
	}
}
