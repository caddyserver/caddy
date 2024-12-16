package metrics

import (
	"net/http"
	"strconv"
)

func SanitizeCode(s int) string {
	switch s {
	case 0, 200:
		return "200"
	default:
		return strconv.Itoa(s)
	}
}

// Only support the list of "regular" HTTP methods, see
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
var methodMap = map[string]string{
	"GET": http.MethodGet, "get": http.MethodGet,
	"HEAD": http.MethodHead, "head": http.MethodHead,
	"PUT": http.MethodPut, "put": http.MethodPut,
	"POST": http.MethodPost, "post": http.MethodPost,
	"DELETE": http.MethodDelete, "delete": http.MethodDelete,
	"CONNECT": http.MethodConnect, "connect": http.MethodConnect,
	"OPTIONS": http.MethodOptions, "options": http.MethodOptions,
	"TRACE": http.MethodTrace, "trace": http.MethodTrace,
	"PATCH": http.MethodPatch, "patch": http.MethodPatch,
}

// SanitizeMethod sanitizes the method for use as a metric label. This helps
// prevent high cardinality on the method label. The name is always upper case.
func SanitizeMethod(m string) string {
	if m, ok := methodMap[m]; ok {
		return m
	}

	return "OTHER"
}
