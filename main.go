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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeconfigPath     = flag.String("kubeconfig", "", "Path to kubeconfig file if running outside the Kubernetes cluster")
	pollingFrequency   = flag.Duration("frequency", time.Minute, "Frequency at which the certificate expiry times are polled")
	namespaces         = flag.String("namespaces", "default", "Comma-separated Kubernetes namespaces to query")
	labels             = flag.String("labels", "", "Label selector that identifies pods to query")
	hostnames          = flag.String("hostnames", "", "Comma-separated SNI hostnames to query")
	port               = flag.Int("port", 443, "TCP port to connect to each pod on")
	loglevel           = flag.String("loglevel", "error", "Log-level threshold for logging messages (debug, info, warn, error, fatal, or panic)")
	logFormat          = flag.String("logformat", "text", "Log format (text or json)")
	metricsPort        = flag.Int("metricsPort", 8888, "TCP port that the Prometheus metrics listener should use")
	insecureSkipVerify = flag.Bool("insecure", true, "If true, then the InsecureSkipVerify option will be used with the TLS connection, and the remote certificate and hostname will be trusted without verification")
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
	kubeClient, err := newClientSet(*kubeconfigPath)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client, exiting: %v", err)
	}

	// start monitor
	monitor := &monitor.CertExpiryMonitor{
		Logger:             logger,
		KubernetesClient:   kubeClient,
		PollingFrequency:   *pollingFrequency,
		Namespaces:         strings.Split(*namespaces, ","),
		Labels:             *labels,
		Hostnames:          strings.Split(*hostnames, ","),
		Port:               *port,
		InsecureSkipVerify: *insecureSkipVerify,
	}
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	go monitor.Run(ctx, wg)

	// switch to healthy
	hh.healthy = true

	// trap signals to terminate
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		logger.Info("Received termination signal, shutting down")
		cancel()
		wg.Wait()
		logger.Info("Shutdown finished, exiting")
	}
}

func runHTTPListener(logger *logrus.Logger, hh *healthHandler) {
	m := http.NewServeMux()
	m.Handle("/healthz", hh)
	m.Handle("/metrics", prometheus.Handler())
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
func newClientSet(kubeconfigPath string) (*kubernetes.Clientset, error) {
	var err error
	var config *rest.Config

	if kubeconfigPath == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
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
