package zipkin

import (
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	zk "github.com/openzipkin/zipkin-go"
	zkhttp "github.com/openzipkin/zipkin-go/middleware/http"
	zkreporter "github.com/openzipkin/zipkin-go/reporter"
	zkreporterhttp "github.com/openzipkin/zipkin-go/reporter/http"
)

type Config struct {
	Reporter                 string
	ReporterHTTPEndpoint     string
	Sampler                  string
	LocalEndpointServiceName string
}

type wrappedHandler struct {
	next httpserver.Handler
	code *int
	err  *error
}

func (wh *wrappedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	*(wh.code), *(wh.err) = wh.next.ServeHTTP(w, r)
}

type Handler struct {
	next   httpserver.Handler
	tracer *zk.Tracer
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (code int, err error) {
	zkhttp.NewServerMiddleware(h.tracer)(&wrappedHandler{
		next: h.next,
		code: &code,
		err:  &err,
	}).ServeHTTP(w, r)
	return
}

func MiddlewareMaker(cfg Config) (func(next httpserver.Handler) httpserver.Handler, error) {
	var rep zkreporter.Reporter
	switch cfg.Reporter {
	case "http":
		rep = zkreporterhttp.NewReporter(cfg.ReporterHTTPEndpoint)
	}

	var sampler zk.Sampler
	switch cfg.Sampler {
	case "always":
		sampler = zk.AlwaysSample
	case "never":
		sampler = zk.NeverSample
	}

	tracer, err := zk.NewTracer(rep, zk.WithSampler(sampler))
	if err != nil {
		return nil, err
	}

	return func(next httpserver.Handler) httpserver.Handler {
		return &Handler{next: next, tracer: tracer}
	}, nil
}
