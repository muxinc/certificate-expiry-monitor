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
	certificateExpired = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_is_expired",
			Help:      "Number of times an expired certificate was found",
		},
		[]string{"ns", "pod", "domain"},
	)
	certificateNotYetValid = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_is_not_yet_valid",
			Help:      "Number of times a certificate was found where it isn't valid yet",
		},
		[]string{"ns", "pod", "domain"},
	)
	certificateValid = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_is_valid",
			Help:      "Number of times a certificate was found to be valid",
		},
		[]string{"ns", "pod", "domain"},
	)
	certificateNotFoundForDomain = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "certificate_expiry_monitor",
			Name:      "certificate_not_found",
			Help:      "Number of times a certificate was not found for a domain",
		},
		[]string{"ns", "pod", "domain"},
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
	prometheus.MustRegister(certificateExpired)
	prometheus.MustRegister(certificateNotYetValid)
	prometheus.MustRegister(certificateValid)
	prometheus.MustRegister(certificateNotFoundForDomain)
	prometheus.MustRegister(certificateSecondsSinceIssued)
	prometheus.MustRegister(certificateSecondsUntilExpires)
}
