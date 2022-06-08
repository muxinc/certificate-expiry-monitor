FROM docker.io/golang:1.17

WORKDIR /src
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o app

FROM alpine:3
RUN apk --no-cache add ca-certificates
COPY --from=0 /src/app /app

CMD ["/app"]
