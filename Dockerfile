FROM golang:1.19.1-alpine as builder

WORKDIR /workspace

COPY go.mod go.sum /workspace/
RUN go mod download

COPY . /workspace/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -ldflags "-s -w" -trimpath -o /go/bin/caddy ./cmd/caddy

FROM alpine

COPY --from=builder /go/bin/caddy /usr/local/bin/caddy
