package push

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type MockedPusher struct {
	http.ResponseWriter
	pushed        map[string]*http.PushOptions
	returnedError error
}

func (w *MockedPusher) Push(target string, options *http.PushOptions) error {
	if w.pushed == nil {
		w.pushed = make(map[string]*http.PushOptions)
	}

	w.pushed[target] = options
	return w.returnedError
}

func TestMiddlewareWillPushResources(t *testing.T) {

	// given
	request, err := http.NewRequest(http.MethodGet, "/index.html", nil)
	writer := httptest.NewRecorder()

	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	middleware := Middleware{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		}),
		Rules: []Rule{
			{Path: "/index.html", Resources: []Resource{
				{Path: "/index.css", Method: http.MethodHead, Header: http.Header{"Test": []string{"Value"}}},
				{Path: "/index2.css", Method: http.MethodGet},
			}},
		},
	}

	pushingWriter := &MockedPusher{ResponseWriter: writer}

	// when
	middleware.ServeHTTP(pushingWriter, request)

	// then
	expectedPushedResources := map[string]*http.PushOptions{
		"/index.css": {
			Method: http.MethodHead,
			Header: http.Header{"Test": []string{"Value"}},
		},

		"/index2.css": {
			Method: http.MethodGet,
			Header: http.Header{},
		},
	}

	comparePushedResources(t, expectedPushedResources, pushingWriter.pushed)
}

func TestMiddlewareWillPushResourcesWithMergedHeaders(t *testing.T) {

	// given
	request, err := http.NewRequest(http.MethodGet, "/index.html", nil)
	request.Header = http.Header{"Accept-Encoding": []string{"br"}, "Invalid-Header": []string{"Should be filter out"}}
	writer := httptest.NewRecorder()

	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	middleware := Middleware{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		}),
		Rules: []Rule{
			{Path: "/index.html", Resources: []Resource{
				{Path: "/index.css", Method: http.MethodHead, Header: http.Header{"Test": []string{"Value"}}},
				{Path: "/index2.css", Method: http.MethodGet},
			}},
		},
	}

	pushingWriter := &MockedPusher{ResponseWriter: writer}

	// when
	middleware.ServeHTTP(pushingWriter, request)

	// then
	expectedPushedResources := map[string]*http.PushOptions{
		"/index.css": {
			Method: http.MethodHead,
			Header: http.Header{"Test": []string{"Value"}, "Accept-Encoding": []string{"br"}},
		},

		"/index2.css": {
			Method: http.MethodGet,
			Header: http.Header{"Accept-Encoding": []string{"br"}},
		},
	}

	comparePushedResources(t, expectedPushedResources, pushingWriter.pushed)
}

func TestMiddlewareShouldntDoRecursivePush(t *testing.T) {

	// given
	request, err := http.NewRequest(http.MethodGet, "/index.css", nil)
	request.Header.Add(pushHeader, "")

	writer := httptest.NewRecorder()

	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	middleware := Middleware{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		}),
		Rules: []Rule{
			{Path: "/", Resources: []Resource{
				{Path: "/index.css", Method: http.MethodHead, Header: http.Header{"Test": []string{"Value"}}},
				{Path: "/index2.css", Method: http.MethodGet},
			}},
		},
	}

	pushingWriter := &MockedPusher{ResponseWriter: writer}

	// when
	middleware.ServeHTTP(pushingWriter, request)

	// then
	if len(pushingWriter.pushed) > 0 {
		t.Errorf("Expected 0 pushed resources, actual %d", len(pushingWriter.pushed))
	}
}

func TestMiddlewareShouldStopPushingOnError(t *testing.T) {

	// given
	request, err := http.NewRequest(http.MethodGet, "/index.html", nil)
	writer := httptest.NewRecorder()

	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	middleware := Middleware{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		}),
		Rules: []Rule{
			{Path: "/index.html", Resources: []Resource{
				{Path: "/only.css", Method: http.MethodHead, Header: http.Header{"Test": []string{"Value"}}},
				{Path: "/index2.css", Method: http.MethodGet},
				{Path: "/index3.css", Method: http.MethodGet},
			}},
		},
	}

	pushingWriter := &MockedPusher{ResponseWriter: writer, returnedError: errors.New("Cannot push right now")}

	// when
	middleware.ServeHTTP(pushingWriter, request)

	// then
	expectedPushedResources := map[string]*http.PushOptions{
		"/only.css": {
			Method: http.MethodHead,
			Header: http.Header{"Test": []string{"Value"}},
		},
	}

	comparePushedResources(t, expectedPushedResources, pushingWriter.pushed)
}

func TestMiddlewareWillNotPushResources(t *testing.T) {
	// given
	request, err := http.NewRequest(http.MethodGet, "/index.html", nil)

	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	middleware := Middleware{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		}),
		Rules: []Rule{
			{Path: "/index.html", Resources: []Resource{
				{Path: "/index.css", Method: http.MethodHead, Header: http.Header{"Test": []string{"Value"}}},
				{Path: "/index2.css", Method: http.MethodGet},
			}},
		},
	}

	writer := httptest.NewRecorder()

	// when
	_, err2 := middleware.ServeHTTP(writer, request)

	// then
	if err2 != nil {
		t.Error("Should not return error")
	}
}

func TestMiddlewareShouldInterceptLinkHeader(t *testing.T) {
	// given
	request, err := http.NewRequest(http.MethodGet, "/index.html", nil)
	writer := httptest.NewRecorder()

	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	middleware := Middleware{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			w.Header().Add("Link", "</index.css>; rel=preload; as=stylesheet;")
			w.Header().Add("Link", "</index2.css>; rel=preload; as=stylesheet;")
			w.Header().Add("Link", "")
			w.Header().Add("Link", "</index3.css>")
			w.Header().Add("Link", "</index4.css>; rel=preload; nopush")
			return 0, nil
		}),
		Rules: []Rule{},
	}

	pushingWriter := &MockedPusher{ResponseWriter: writer}

	// when
	_, err2 := middleware.ServeHTTP(pushingWriter, request)

	// then
	if err2 != nil {
		t.Error("Should not return error")
	}

	expectedPushedResources := map[string]*http.PushOptions{
		"/index.css": {
			Method: http.MethodGet,
			Header: http.Header{},
		},
		"/index2.css": {
			Method: http.MethodGet,
			Header: http.Header{},
		},
		"/index3.css": {
			Method: http.MethodGet,
			Header: http.Header{},
		},
	}

	comparePushedResources(t, expectedPushedResources, pushingWriter.pushed)
}

func TestMiddlewareShouldInterceptLinkHeaderPusherError(t *testing.T) {
	// given
	expectedHeaders := http.Header{"Accept-Encoding": []string{"br"}}
	request, err := http.NewRequest(http.MethodGet, "/index.html", nil)
	request.Header = http.Header{"Accept-Encoding": []string{"br"}, "Invalid-Header": []string{"Should be filter out"}}

	writer := httptest.NewRecorder()

	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	middleware := Middleware{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			w.Header().Add("Link", "</index.css>; rel=preload; as=stylesheet;")
			w.Header().Add("Link", "</index2.css>; rel=preload; as=stylesheet;")
			return 0, nil
		}),
		Rules: []Rule{},
	}

	pushingWriter := &MockedPusher{ResponseWriter: writer, returnedError: errors.New("Cannot push right now")}

	// when
	_, err2 := middleware.ServeHTTP(pushingWriter, request)

	// then
	if err2 != nil {
		t.Error("Should not return error")
	}

	expectedPushedResources := map[string]*http.PushOptions{
		"/index.css": {
			Method: http.MethodGet,
			Header: expectedHeaders,
		},
	}

	comparePushedResources(t, expectedPushedResources, pushingWriter.pushed)
}

func comparePushedResources(t *testing.T, expected, actual map[string]*http.PushOptions) {
	if len(expected) != len(actual) {
		t.Errorf("Expected %d pushed resources, actual: %d", len(expected), len(actual))
	}

	for target, expectedTarget := range expected {
		if actualTarget, exists := actual[target]; exists {

			if expectedTarget.Method != actualTarget.Method {
				t.Errorf("Expected %s resource method to be %s, actual: %s", target, expectedTarget.Method, actualTarget.Method)
			}

			if !reflect.DeepEqual(expectedTarget.Header, actualTarget.Header) {
				t.Errorf("Expected %s resource push headers to be %+v, actual: %+v", target, expectedTarget.Header, actualTarget.Header)
			}
		} else {
			t.Errorf("Expected %s to be pushed", target)
		}
	}
}
