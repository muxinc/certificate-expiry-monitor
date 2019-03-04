package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const tlsConnectionTimeout = 5 * time.Second

// CertExpiryMonitor periodically checks certificate expiry times
type CertExpiryMonitor struct {
	Logger             *logrus.Logger
	KubernetesClient   *kubernetes.Clientset
	PollingFrequency   time.Duration
	Namespaces         []string
	Labels             string
	Domains            []string
	Port               int
	InsecureSkipVerify bool
}

// Run the monitor until instructed to stop
func (m *CertExpiryMonitor) Run(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	defer wg.Done()

	// setup list options
	listOptions := metav1.ListOptions{
		LabelSelector: m.Labels,
	}
	api := m.KubernetesClient.CoreV1()
	ticker := time.NewTicker(m.PollingFrequency)

	for {
		m.Logger.Debug("Polling")

		// iterate over namespaces to monitor
		for _, ns := range m.Namespaces {
			// list pods matching the labels in this namespace
			pods, err := api.Pods(ns).List(listOptions)
			if err != nil {
				return err
			}

			// iterate over matching pods in namespace
			matchingPods.WithLabelValues(ns).Set(float64(len(pods.Items)))
			m.Logger.WithField("ns", ns).Debugf("Number of matching pods found in namespace: %d", len(pods.Items))
			podsWG := &sync.WaitGroup{}
			for _, pod := range pods.Items {
				go m.checkCertificates(podsWG, ns, pod.Name, pod.Status.HostIP)
			}
			podsWG.Wait()
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			m.Logger.Info("Monitor stopping")
			return nil
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
				certificateExpired.WithLabelValues(namespace, pod, domain).Set(1)
			} else if cert.NotBefore.After(currentTime) {
				certLogger.Warnf("Certificate is not yet valid: Not-Before=%v", cert.NotBefore)
				certificateNotYetValid.WithLabelValues(namespace, pod, domain).Set(1)
			} else {
				certLogger.Debugf("Certificate is valid")
				certificateValid.WithLabelValues(namespace, pod, domain).Set(1)
			}
			certificateSecondsSinceIssued.WithLabelValues(namespace, pod, domain).Set(currentTime.Sub(cert.NotBefore).Seconds())
			certificateSecondsUntilExpires.WithLabelValues(namespace, pod, domain).Set(cert.NotAfter.Sub(currentTime).Seconds())
			break
		}

		if !certFound {
			logger.Warn("No matching certificates found for domain")
			certificateNotFoundForDomain.WithLabelValues(namespace, pod, domain).Inc()
		}
		if err := conn.Close(); err != nil {
			tlsCloseConnectionError.WithLabelValues(namespace, pod, domain).Inc()
			logger.Errorf("Error closing TLS connection after checking certificates: %v", err)
		}
	}
}
