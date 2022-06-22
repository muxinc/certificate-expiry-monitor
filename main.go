package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/muxinc/certificate-expiry-monitor/monitor"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeconfigPath     = flag.String("kubeconfig", "", "Path to kubeconfig file if running outside the Kubernetes cluster")
	kubeContext        = flag.String("context", "", "The name of the kubeconfig context to use if running outside the Kubernetes cluster")
	pollingFrequency   = flag.Duration("frequency", time.Minute, "Frequency at which the certificate expiry times are polled")
	namespaces         = flag.String("namespaces", "default", "Comma-separated Kubernetes namespaces to query")
	labels             = flag.String("labels", "", "Label selector that identifies pods to query")
	ingressNamespaces  = flag.String("ingressNamespaces", "", "If provided, a comma-separated list of namespaces that will be searched for ingresses with domains to automatically query")
	domains            = flag.String("domains", "", "Comma-separated SNI domains to query")
	ignoredDomains     = flag.String("ignoredDomains", "", "Comma-separated list of domains to exclude from the discovered set. This can be a regex if the string is wrapped in forward-slashes like /.*\\.domain\\.com$/ which would exclude all domain.com subdomains.")
	hostIP             = flag.Bool("hostIP", false, "If true, then connect to the host that the pod is running on rather than to the pod itself.")
	dialTargetAddr     = flag.String("dial_target_addr", "", "If provided, dials this address directly rather than resolving pods")
	dialTargetName     = flag.String("dial_target_name", "", "Must be provided if dial_target_addr is set, identifies the explicitly configured target in the monitoring labels (still uses the pod label).")
	port               = flag.Int("port", 443, "TCP port to connect to each pod on")
	loglevel           = flag.String("loglevel", "error", "Log-level threshold for logging messages (debug, info, warn, error, fatal, or panic)")
	logFormat          = flag.String("logformat", "text", "Log format (text or json)")
	metricsPort        = flag.Int("metricsPort", 8888, "TCP port that the Prometheus metrics listener should use")
	insecureSkipVerify = flag.Bool("insecure", true, "If true, then the InsecureSkipVerify option will be used with the TLS connection, and the remote certificate and hostname will be trusted without verification")
	ingressAPIVersion  = flag.String("ingressAPIVersion", "extensions/v1beta1", "Version of the Ingress API to use, can be either `extensions/v1beta1` or `networking/v1`")
)

func main() {
	// parse input flags
	flag.Parse()

	// create logging instance
	logger := newLogger(*loglevel, *logFormat)

	// start HTTP listener with Prometheus metrics and healthcheck endpoints
	hh := &healthHandler{healthy: false}
	runHTTPListener(logger, hh)

	// create Kubernetes client
	kubeClient, err := newClientSet(*kubeconfigPath, *kubeContext)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client, exiting: %v", err)
	}

	if len(*dialTargetAddr) > 0 && len(*dialTargetName) == 0 {
		log.Fatalf("got a dial target address but not a name. must set -dial_target_name")
	}

	// start monitor
	monitor := &monitor.CertExpiryMonitor{
		Logger:             logger,
		KubernetesClient:   kubeClient,
		PollingFrequency:   *pollingFrequency,
		Namespaces:         strings.Split(*namespaces, ","),
		Labels:             *labels,
		IngressNamespaces:  strings.Split(*ingressNamespaces, ","),
		Domains:            strings.Split(*domains, ","),
		IgnoredDomains:     strings.Split(*ignoredDomains, ","),
		HostIP:             *hostIP,
		DialTargetAddr:     *dialTargetAddr,
		DialTargetName:     *dialTargetName,
		Port:               *port,
		InsecureSkipVerify: *insecureSkipVerify,
		IngressAPIVersion:  *ingressAPIVersion,
	}
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go monitor.Run(ctx, wg)

	// switch to healthy
	hh.healthy = true

	// trap signals to terminate
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Info("Received termination signal, shutting down")
	cancel()
	wg.Wait()
	logger.Info("Shutdown finished, exiting")
}

func runHTTPListener(logger *logrus.Logger, hh *healthHandler) {
	m := http.NewServeMux()
	m.Handle("/healthz", hh)
	m.Handle("/metrics", promhttp.Handler())
	logger.Infof("Starting Prometheus metrics endpoint on :%d", *metricsPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *metricsPort))
	if err != nil {
		logger.Fatalf("Failed to start Prometheus metrics endpoint: %v", err)
	}
	go http.Serve(lis, m)
}

func newLogger(level, format string) *logrus.Logger {
	var logger = logrus.New()
	logger.Out = os.Stderr

	switch strings.ToLower(format) {
	case "text":
		textFormatter := new(logrus.TextFormatter)
		textFormatter.TimestampFormat = time.RFC3339Nano
		logger.Formatter = textFormatter
	case "json":
		jsonFormatter := new(logrus.JSONFormatter)
		jsonFormatter.TimestampFormat = time.RFC3339Nano
		logger.Formatter = jsonFormatter
	default:
		log.Fatalf("Unrecognized log format, exiting: %s", format)
	}

	switch strings.ToLower(level) {
	case "debug":
		logger.Level = logrus.DebugLevel
	case "info":
		logger.Level = logrus.InfoLevel
	case "error":
		logger.Level = logrus.ErrorLevel
	case "warn":
		logger.Level = logrus.WarnLevel
	case "fatal":
		logger.Level = logrus.FatalLevel
	case "panic":
		logger.Level = logrus.PanicLevel
	default:
		log.Fatalf("Unrecognized log level, exiting: %s", level)
	}

	return logger
}

// Create new Kubernetes's clientSet.
// When configured env.KubeconfigPath, read config from env.KubeconfigPath.
// When not configured env.KubeconfigPath, read internal cluster config.
func newClientSet(kubeconfigPath string, kubeContext string) (*kubernetes.Clientset, error) {
	var err error
	var config *rest.Config

	if kubeconfigPath == "" {
		config, err = rest.InClusterConfig()
	} else {
		configOverrides := &clientcmd.ConfigOverrides{}
		if kubeContext != "" {
			configOverrides.CurrentContext = kubeContext
		}
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
			configOverrides).ClientConfig()
	}
	if err != nil {
		return nil, err
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientSet, nil
}

type healthHandler struct {
	healthy bool
}

func (hh *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if hh.healthy {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Healthy"))
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Unhealthy"))
}
