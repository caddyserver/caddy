package caddy

import (
	"net/http"
	"net/url"
)

type ProxyFuncProducer interface {
	ProxyFunc() func(*http.Request) (*url.URL, error)
}
