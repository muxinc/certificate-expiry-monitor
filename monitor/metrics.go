package monitor

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	matchingPods = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "matching_pods",
			Help:      "Number of pods that match the label filter in a namespace",
		},
		[]string{"ns"},
	)
	tlsOpenConnectionError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "tls_open_connection_error",
			Help:      "Number of times an error was encountered while opening a TLS connection to a pod",
		},
		[]string{"ns", "pod", "domain"},
	)
	tlsCloseConnectionError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "tls_close_connection_error",
			Help:      "Number of times an error was encountered while closing a TLS connection to a pod",
		},
		[]string{"ns", "pod", "domain"},
	)
	certificateStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate",
			Help:      "Number of instances of pods & domains in a given status",
		},
		[]string{"ns", "pod", "domain", "status"},
	)
	certificateSecondsSinceIssued = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "seconds_since_cert_issued",
			Help:      "Secods since the certificate was issued",
		},
		[]string{"ns", "pod", "domain"},
	)
	certificateSecondsUntilExpires = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "seconds_until_cert_expires",
			Help:      "Seconds until the certificate expires",
		},
		[]string{"ns", "pod", "domain"},
	)
)

func init() {
	prometheus.MustRegister(matchingPods)
	prometheus.MustRegister(tlsOpenConnectionError)
	prometheus.MustRegister(tlsCloseConnectionError)
	prometheus.MustRegister(certificateStatus)
	prometheus.MustRegister(certificateSecondsSinceIssued)
	prometheus.MustRegister(certificateSecondsUntilExpires)
}
