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
		[]string{"namespace"},
	)
	tlsOpenConnectionError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "tls_open_connection_error",
			Help:      "Number of times an error was encountered while opening a TLS connection to a pod",
		},
		[]string{"namespace", "pod", "hostname"},
	)
	tlsCloseConnectionError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "tls_close_connection_error",
			Help:      "Number of times an error was encountered while closing a TLS connection to a pod",
		},
		[]string{"namespace", "pod", "hostname"},
	)
	certificateExpired = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_is_expired",
			Help:      "Number of times an expired certificate was found",
		},
		[]string{"namespace", "pod", "hostname"},
	)
	certificateNotYetValid = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_is_not_yet_valid",
			Help:      "Number of times a certificate was found where it isn't valid yet",
		},
		[]string{"namespace", "pod", "hostname"},
	)
	certificateValid = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_is_valid",
			Help:      "Number of times a certificate was found to be valid",
		},
		[]string{"namespace", "pod", "hostname"},
	)
	certificateNotFoundForHostname = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_not_found",
			Help:      "Number of times a certificate was not found for a hostname",
		},
		[]string{"namespace", "pod", "hostname"},
	)
	certificateSecondsSinceIssued = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "seconds_since_cert_issued",
			Help:      "Secods since the certificate was issued",
		},
		[]string{"namespace", "pod", "hostname"},
	)
	certificateSecondsUntilExpires = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "seconds_until_cert_expires",
			Help:      "Seconds until the certificate expires",
		},
		[]string{"namespace", "pod", "hostname"},
	)
)

func init() {
	prometheus.MustRegister(matchingPods)
	prometheus.MustRegister(tlsOpenConnectionError)
	prometheus.MustRegister(tlsCloseConnectionError)
	prometheus.MustRegister(certificateExpired)
	prometheus.MustRegister(certificateNotYetValid)
	prometheus.MustRegister(certificateValid)
	prometheus.MustRegister(certificateNotFoundForHostname)
	prometheus.MustRegister(certificateSecondsSinceIssued)
	prometheus.MustRegister(certificateSecondsUntilExpires)
}
