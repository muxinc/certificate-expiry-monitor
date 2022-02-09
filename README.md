<img src="https://banner.mux.dev/?text=TLS%20Expiry%20Monitor" />

Utility that exposes the expiry of TLS certificates as Prometheus metrics

## Building
To build the Docker image, simply run `docker build`:
```
docker build . -t muxinc/certificate-expiry-monitor:latest
```

## Running
Run the Docker image using the executable at `/app`:
```
→ docker run muxinc/certificate-expiry-monitor:latest /app --help
Usage of ./certificate-expiry-monitor:
  -context string
    	The name of the kubeconfig context to use if running outside the Kubernetes cluster
  -domains string
    	Comma-separated SNI domains to query
  -frequency duration
    	Frequency at which the certificate expiry times are polled (default 1m0s)
  -hostIP
    	If true, then connect to the host that the pod is running on rather than to the pod itself.
  -ignoredDomains string
    	Comma-separated list of domains to exclude from the discovered set. This can be a regex if the string is wrapped in forward-slashes like /.*\.domain\.com$/ which would exclude all domain.com subdomains.
  -ingressAPIVersion extensions/v1beta1
    	Version of the Ingress API to use, can be either extensions/v1beta1 or `networking/v1` (default "extensions/v1beta1")
  -ingressNamespaces string
    	If provided, a comma-separated list of namespaces that will be searched for ingresses with domains to automatically query
  -insecure
    	If true, then the InsecureSkipVerify option will be used with the TLS connection, and the remote certificate and hostname will be trusted without verification (default true)
  -kubeconfig string
    	Path to kubeconfig file if running outside the Kubernetes cluster
  -labels string
    	Label selector that identifies pods to query
  -logformat string
    	Log format (text or json) (default "text")
  -loglevel string
    	Log-level threshold for logging messages (debug, info, warn, error, fatal, or panic) (default "error")
  -metricsPort int
    	TCP port that the Prometheus metrics listener should use (default 8888)
  -namespaces string
    	Comma-separated Kubernetes namespaces to query (default "default")
  -port int
    	TCP port to connect to each pod on (default 443)
```

### Kubernetes Manifest
You're probably going to want to run the certificate-expiry monitor in a Kubernetes cluster. The following manifest shows how you might monitor a set of ingress pods matching the label `k8s-app=my-ingresses` in the `default` namespace for the `foobar.example.com` domain:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: certificate-expiry-monitor
  namespace: default
spec:
  minReadySeconds: 5
  revisionHistoryLimit: 3
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: certificate-expiry-monitor
    spec:
      containers:
      - command:
        - /app
        - -labels
        - k8s-app=my-ingresses
        - -namespaces
        - default
        - -frequency
        - 1m
        - -domains
        - foobar.example.com
        image: muxinc/certificate-expiry-monitor:latest
        imagePullPolicy: Always
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8888
          initialDelaySeconds: 5
          timeoutSeconds: 5
        name: certificate-expiry-monitor
        resources:
          limits:
            cpu: 20m
            memory: 50Mi
          requests:
            cpu: 20m
            memory: 50Mi
```

## Monitoring
A Prometheus endpoint is available at `/metrics` on TCP port `:8888` (customizable with `metricsPort`).

### Labels
| Name  | Description  |
|---|---|
| `ns` | Namespace of the pod that was queried |
| `pod` | Pod being queried for TLS certificates |
| `domain` | Domain being verified against TLS certificates |
| `status` | Certificate is either `valid`, `expired`, `soon` (not yet valid), or `notfound` |

### Gauges
| Name  | Labels | Description  |
|---|---|---|
| `certificate_expiry_monitor_matching_pods` | `ns` | Number of pods that match the label filter in a namespace  |
| `certificate_expiry_monitor_certificate`  | `ns`, `pod`, `domain`, `status` | Number of pods with a certificate in a given status for the domain |
| `certificate_expiry_monitor_seconds_since_cert_issued`  | `ns`, `pod`, `domain` | Seconds since the certificate was issued  |
| `certificate_expiry_monitor_seconds_until_cert_expires`  | `ns`, `pod`, `domain` | Seconds until the certificate expires  |

### Counters
| Name  | Labels | Description  |
|---|---|---|
| `certificate_expiry_monitor_tls_open_connection_error`  | `ns`, `pod`, `domain` | Number of times an error occurred while opening a TLS connection to a pod |
| `certificate_expiry_monitor_tls_close_connection_error`  | `ns`, `pod`, `domain` | Number of times an error occurred while closing a TLS connection to a pod |

## Healthcheck
A simple healthcheck is available at `/healthz` on the TCP port `:8888` (customizable with `metricsPort`):

```
→ curl -v http://localhost:8888/healthz
*   Trying ::1...
* TCP_NODELAY set
* Connection failed
* connect to ::1 port 8888 failed: Connection refused
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8888 (#0)
> GET /healthz HTTP/1.1
> Host: localhost:8888
> User-Agent: curl/7.52.1
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Mon, 04 Mar 2019 17:56:45 GMT
< Content-Length: 7
< Content-Type: text/plain; charset=utf-8
<
* Curl_http_done: called premature == 0
* Connection #0 to host localhost left intact
Healthy
```
