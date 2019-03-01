package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CertExpiryMonitor periodically checks certificate expiry times
type CertExpiryMonitor struct {
	Logger             *logrus.Logger
	KubernetesClient   *kubernetes.Clientset
	PollingFrequency   time.Duration
	Namespaces         []string
	Labels             string
	Hostnames          []string
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

	// iterate over hostnames that need to be checked, setting the hostname in the TLS connection config for SNI
	for _, hostname := range m.Hostnames {
		logger := m.Logger.WithFields(logrus.Fields{"ns": namespace, "pod": pod, "hostname": hostname})

		// connect to the pod over TLS
		tlsConfig.ServerName = hostname
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", podIP, m.Port), &tlsConfig)
		if err != nil {
			tlsOpenConnectionError.WithLabelValues(namespace, pod, hostname).Inc()
			logger.Errorf("Error connecting to pod to check certificates: %v", err)
			return
		}

		// iterate over certificates returned by pod, looking for once that matches the hostname we're verifying
		certFound := false
		for _, cert := range conn.ConnectionState().PeerCertificates {
			if cert.VerifyHostname(hostname) == nil {
				certFound = true
				certValid := true
				certLogger := logger.WithField("subject", cert.Subject)
				certLogger.Debugf("Checking certificate: Not-Before=%v Not-After=%v", cert.NotBefore, cert.NotAfter)
				if cert.NotAfter.Before(currentTime) {
					certValid = false
					certLogger.Warnf("Certificate has expired: Not-After=%v", cert.NotAfter)
					certificateExpired.WithLabelValues(namespace, pod, hostname).Inc()
				}
				if cert.NotBefore.After(currentTime) {
					certValid = false
					certLogger.Warnf("Certificate is not yet valid: Not-Before=%v", cert.NotBefore)
					certificateNotYetValid.WithLabelValues(namespace, pod, hostname).Inc()
				}
				if certValid {
					certLogger.Debugf("Certificate is valid")
					certificateValid.WithLabelValues(namespace, pod, hostname).Inc()
				}
				certificateSecondsSinceIssued.WithLabelValues(namespace, pod, hostname).Set(currentTime.Sub(cert.NotBefore).Seconds())
				certificateSecondsUntilExpires.WithLabelValues(namespace, pod, hostname).Set(cert.NotAfter.Sub(currentTime).Seconds())
				break
			}
		}

		if !certFound {
			logger.Warn("No matching certificates found for hostname")
			certificateNotFoundForHostname.WithLabelValues(namespace, pod, hostname).Inc()
		}
		if err := conn.Close(); err != nil {
			tlsCloseConnectionError.WithLabelValues(namespace, pod, hostname).Inc()
			logger.Errorf("Error closing TLS connection after checking certificates: %v", err)
		}
	}
}
