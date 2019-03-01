FROM golang:1.12

WORKDIR /go/src/github.com/muxinc/certificate-expiry-monitor

RUN go get github.com/golang/dep/cmd/dep
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure -v -vendor-only

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go install -v \
            -ldflags="-w -s" \
            -ldflags "-X main.serviceName=certificate-expiry-monitor" \
            github.com/muxinc/certificate-expiry-monitor

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=0 /go/bin/certificate-expiry-monitor /app

CMD ["/app"]
