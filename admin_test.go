// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var testCfg = []byte(`{
			"apps": {
				"http": {
					"servers": {
						"myserver": {
							"listen": ["tcp/localhost:8080-8084"],
							"read_timeout": "30s"
						},
						"yourserver": {
							"listen": ["127.0.0.1:5000"],
							"read_header_timeout": "15s"
						}
					}
				}
			}
		}
		`)

func TestUnsyncedConfigAccess(t *testing.T) {
	// each test is performed in sequence, so
	// each change builds on the previous ones;
	// the config is not reset between tests
	for i, tc := range []struct {
		method    string
		path      string // rawConfigKey will be prepended
		payload   string
		expect    string // JSON representation of what the whole config is expected to be after the request
		shouldErr bool
	}{
		{
			method:  "POST",
			path:    "",
			payload: `{"foo": "bar", "list": ["a", "b", "c"]}`, // starting value
			expect:  `{"foo": "bar", "list": ["a", "b", "c"]}`,
		},
		{
			method:  "POST",
			path:    "/foo",
			payload: `"jet"`,
			expect:  `{"foo": "jet", "list": ["a", "b", "c"]}`,
		},
		{
			method:  "POST",
			path:    "/bar",
			payload: `{"aa": "bb", "qq": "zz"}`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb", "qq": "zz"}, "list": ["a", "b", "c"]}`,
		},
		{
			method: "DELETE",
			path:   "/bar/qq",
			expect: `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c"]}`,
		},
		{
			method:    "DELETE",
			path:      "/bar/qq",
			expect:    `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c"]}`,
			shouldErr: true,
		},
		{
			method:  "POST",
			path:    "/list",
			payload: `"e"`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "e"]}`,
		},
		{
			method:  "PUT",
			path:    "/list/3",
			payload: `"d"`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d", "e"]}`,
		},
		{
			method: "DELETE",
			path:   "/list/3",
			expect: `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "e"]}`,
		},
		{
			method:  "PATCH",
			path:    "/list/3",
			payload: `"d"`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d"]}`,
		},
		{
			method:  "POST",
			path:    "/list/...",
			payload: `["e", "f", "g"]`,
			expect:  `{"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d", "e", "f", "g"]}`,
		},
	} {
		err := unsyncedConfigAccess(tc.method, rawConfigKey+tc.path, []byte(tc.payload), nil)

		if tc.shouldErr && err == nil {
			t.Fatalf("Test %d: Expected error return value, but got: %v", i, err)
		}
		if !tc.shouldErr && err != nil {
			t.Fatalf("Test %d: Should not have had error return value, but got: %v", i, err)
		}

		// decode the expected config so we can do a convenient DeepEqual
		var expectedDecoded any
		err = json.Unmarshal([]byte(tc.expect), &expectedDecoded)
		if err != nil {
			t.Fatalf("Test %d: Unmarshaling expected config: %v", i, err)
		}

		// make sure the resulting config is as we expect it
		if !reflect.DeepEqual(rawCfg[rawConfigKey], expectedDecoded) {
			t.Fatalf("Test %d:\nExpected:\n\t%#v\nActual:\n\t%#v",
				i, expectedDecoded, rawCfg[rawConfigKey])
		}
	}
}

// TestLoadConcurrent exercises Load under concurrent conditions
// and is most useful under test with `-race` enabled.
func TestLoadConcurrent(t *testing.T) {
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			_ = Load(testCfg, true)
			wg.Done()
		}()
	}
	wg.Wait()
}

type fooModule struct {
	IntField int
	StrField string
}

func (fooModule) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "foo",
		New: func() Module { return new(fooModule) },
	}
}
func (fooModule) Start() error { return nil }
func (fooModule) Stop() error  { return nil }

func TestETags(t *testing.T) {
	RegisterModule(fooModule{})

	if err := Load([]byte(`{"admin": {"listen": "localhost:2999"}, "apps": {"foo": {"strField": "abc", "intField": 0}}}`), true); err != nil {
		t.Fatalf("loading: %s", err)
	}

	const key = "/" + rawConfigKey + "/apps/foo"

	// try update the config with the wrong etag
	err := changeConfig(http.MethodPost, key, []byte(`{"strField": "abc", "intField": 1}}`), fmt.Sprintf(`"/%s not_an_etag"`, rawConfigKey), false)
	if apiErr, ok := err.(APIError); !ok || apiErr.HTTPStatus != http.StatusPreconditionFailed {
		t.Fatalf("expected precondition failed; got %v", err)
	}

	// get the etag
	hash := etagHasher()
	if err := readConfig(key, hash); err != nil {
		t.Fatalf("reading: %s", err)
	}

	// do the same update with the correct key
	err = changeConfig(http.MethodPost, key, []byte(`{"strField": "abc", "intField": 1}`), makeEtag(key, hash), false)
	if err != nil {
		t.Fatalf("expected update to work; got %v", err)
	}

	// now try another update. The hash should no longer match and we should get precondition failed
	err = changeConfig(http.MethodPost, key, []byte(`{"strField": "abc", "intField": 2}`), makeEtag(key, hash), false)
	if apiErr, ok := err.(APIError); !ok || apiErr.HTTPStatus != http.StatusPreconditionFailed {
		t.Fatalf("expected precondition failed; got %v", err)
	}
}

func BenchmarkLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Load(testCfg, true)
	}
}

func TestAdminHandlerErrorHandling(t *testing.T) {
	initAdminMetrics()

	handler := adminHandler{
		mux: http.NewServeMux(),
	}

	handler.mux.Handle("/error", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := fmt.Errorf("test error")
		handler.handleError(w, r, err)
	}))

	req := httptest.NewRequest(http.MethodGet, "/error", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Error("expected error response, got success")
	}

	var apiErr APIError
	if err := json.NewDecoder(rr.Body).Decode(&apiErr); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if apiErr.Message != "test error" {
		t.Errorf("expected error message 'test error', got '%s'", apiErr.Message)
	}
}

func initAdminMetrics() {
	if adminMetrics.requestErrors != nil {
		prometheus.Unregister(adminMetrics.requestErrors)
	}
	if adminMetrics.requestCount != nil {
		prometheus.Unregister(adminMetrics.requestCount)
	}

	adminMetrics.requestErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "caddy",
		Subsystem: "admin_http",
		Name:      "request_errors_total",
		Help:      "Number of errors that occurred handling admin endpoint requests",
	}, []string{"handler", "path", "method"})

	adminMetrics.requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "caddy",
		Subsystem: "admin_http",
		Name:      "requests_total",
		Help:      "Count of requests to the admin endpoint",
	}, []string{"handler", "path", "code", "method"}) // Added code and method labels

	prometheus.MustRegister(adminMetrics.requestErrors)
	prometheus.MustRegister(adminMetrics.requestCount)
}

func TestAdminHandlerBuiltinRouteErrors(t *testing.T) {
	initAdminMetrics()

	cfg := &Config{
		Admin: &AdminConfig{
			Listen: "localhost:2019",
		},
	}

	err := replaceLocalAdminServer(cfg, Context{})
	if err != nil {
		t.Fatalf("setting up admin server: %v", err)
	}
	defer func() {
		stopAdminServer(localAdminServer)
	}()

	tests := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
	}{
		{
			name:           "stop endpoint wrong method",
			path:           "/stop",
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "config endpoint wrong content-type",
			path:           "/config/",
			method:         http.MethodPost,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "config ID missing ID",
			path:           "/id/",
			method:         http.MethodGet,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, fmt.Sprintf("http://localhost:2019%s", test.path), nil)
			rr := httptest.NewRecorder()

			localAdminServer.Handler.ServeHTTP(rr, req)

			if rr.Code != test.expectedStatus {
				t.Errorf("expected status %d but got %d", test.expectedStatus, rr.Code)
			}

			metricValue := testGetMetricValue(map[string]string{
				"path":    test.path,
				"handler": "admin",
				"method":  test.method,
			})
			if metricValue != 1 {
				t.Errorf("expected error metric to be incremented once, got %v", metricValue)
			}
		})
	}
}

func testGetMetricValue(labels map[string]string) float64 {
	promLabels := prometheus.Labels{}
	for k, v := range labels {
		promLabels[k] = v
	}

	metric, err := adminMetrics.requestErrors.GetMetricWith(promLabels)
	if err != nil {
		return 0
	}

	pb := &dto.Metric{}
	metric.Write(pb)
	return pb.GetCounter().GetValue()
}

type mockRouter struct {
	routes []AdminRoute
}

func (m mockRouter) Routes() []AdminRoute {
	return m.routes
}

type mockModule struct {
	mockRouter
}

func (m *mockModule) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID: "admin.api.mock",
		New: func() Module {
			mm := &mockModule{
				mockRouter: mockRouter{
					routes: m.routes,
				},
			}
			return mm
		},
	}
}

func TestNewAdminHandlerRouterRegistration(t *testing.T) {
	originalModules := make(map[string]ModuleInfo)
	for k, v := range modules {
		originalModules[k] = v
	}
	defer func() {
		modules = originalModules
	}()

	mockRoute := AdminRoute{
		Pattern: "/mock",
		Handler: AdminHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		}),
	}

	mock := &mockModule{
		mockRouter: mockRouter{
			routes: []AdminRoute{mockRoute},
		},
	}
	RegisterModule(mock)

	addr, err := ParseNetworkAddress("localhost:2019")
	if err != nil {
		t.Fatalf("Failed to parse address: %v", err)
	}

	admin := &AdminConfig{
		EnforceOrigin: false,
	}
	handler := admin.newAdminHandler(addr, false, Context{})

	req := httptest.NewRequest("GET", "/mock", nil)
	req.Host = "localhost:2019"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d but got %d", http.StatusOK, rr.Code)
		t.Logf("Response body: %s", rr.Body.String())
	}

	if len(admin.routers) != 1 {
		t.Errorf("Expected 1 router to be stored, got %d", len(admin.routers))
	}
}

type mockProvisionableRouter struct {
	mockRouter
	provisionErr error
	provisioned  bool
}

func (m *mockProvisionableRouter) Provision(Context) error {
	m.provisioned = true
	return m.provisionErr
}

type mockProvisionableModule struct {
	*mockProvisionableRouter
}

func (m *mockProvisionableModule) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID: "admin.api.mock_provision",
		New: func() Module {
			mm := &mockProvisionableModule{
				mockProvisionableRouter: &mockProvisionableRouter{
					mockRouter:   m.mockRouter,
					provisionErr: m.provisionErr,
				},
			}
			return mm
		},
	}
}

func TestAdminRouterProvisioning(t *testing.T) {
	tests := []struct {
		name         string
		provisionErr error
		wantErr      bool
		routersAfter int // expected number of routers after provisioning
	}{
		{
			name:         "successful provisioning",
			provisionErr: nil,
			wantErr:      false,
			routersAfter: 0,
		},
		{
			name:         "provisioning error",
			provisionErr: fmt.Errorf("provision failed"),
			wantErr:      true,
			routersAfter: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalModules := make(map[string]ModuleInfo)
			for k, v := range modules {
				originalModules[k] = v
			}
			defer func() {
				modules = originalModules
			}()

			mockRoute := AdminRoute{
				Pattern: "/mock",
				Handler: AdminHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return nil
				}),
			}

			// Create provisionable module
			mock := &mockProvisionableModule{
				mockProvisionableRouter: &mockProvisionableRouter{
					mockRouter: mockRouter{
						routes: []AdminRoute{mockRoute},
					},
					provisionErr: test.provisionErr,
				},
			}
			RegisterModule(mock)

			admin := &AdminConfig{}
			addr, err := ParseNetworkAddress("localhost:2019")
			if err != nil {
				t.Fatalf("Failed to parse address: %v", err)
			}

			_ = admin.newAdminHandler(addr, false, Context{})
			err = admin.provisionAdminRouters(Context{})

			if test.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}

			if len(admin.routers) != test.routersAfter {
				t.Errorf("Expected %d routers after provisioning, got %d", test.routersAfter, len(admin.routers))
			}
		})
	}
}

func TestAllowedOriginsUnixSocket(t *testing.T) {
	tests := []struct {
		name          string
		addr          NetworkAddress
		origins       []string
		expectOrigins []string
	}{
		{
			name: "unix socket with default origins",
			addr: NetworkAddress{
				Network: "unix",
				Host:    "/tmp/caddy.sock",
			},
			origins: nil, // default origins
			expectOrigins: []string{
				"", // empty host as per RFC 2616
				"127.0.0.1",
				"::1",
			},
		},
		{
			name: "unix socket with custom origins",
			addr: NetworkAddress{
				Network: "unix",
				Host:    "/tmp/caddy.sock",
			},
			origins: []string{"example.com"},
			expectOrigins: []string{
				"example.com",
			},
		},
		{
			name: "tcp socket on localhost gets all loopback addresses",
			addr: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 2019,
				EndPort:   2019,
			},
			origins: nil,
			expectOrigins: []string{
				"localhost:2019",
				"[::1]:2019",
				"127.0.0.1:2019",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admin := AdminConfig{
				Origins: test.origins,
			}

			got := admin.allowedOrigins(test.addr)

			var gotOrigins []string
			for _, u := range got {
				gotOrigins = append(gotOrigins, u.Host)
			}

			if len(gotOrigins) != len(test.expectOrigins) {
				t.Errorf("Expected %d origins but got %d", len(test.expectOrigins), len(gotOrigins))
				return
			}

			expectMap := make(map[string]struct{})
			for _, origin := range test.expectOrigins {
				expectMap[origin] = struct{}{}
			}

			gotMap := make(map[string]struct{})
			for _, origin := range gotOrigins {
				gotMap[origin] = struct{}{}
			}

			if !reflect.DeepEqual(expectMap, gotMap) {
				t.Errorf("Origins mismatch.\nExpected: %v\nGot: %v", test.expectOrigins, gotOrigins)
			}
		})
	}
}

func TestReplaceRemoteAdminServer(t *testing.T) {
	const testCert = `MIIDCTCCAfGgAwIBAgIUXsqJ1mY8pKlHQtI3HJ23x2eZPqwwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIzMDEwMTAwMDAwMFoXDTI0MDEw
MTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4O4S6BSoYcoxvRqI+h7yPOjF6KjntjzVVm9M+uHK4lzX
F1L3pSxJ2nDD4wZEV3FJ5yFOHVFqkG2vXG3BIczOlYG7UeNmKbQnKc5kZj3HGUrS
VGEktA4OJbeZhhWP15gcXN5eDM2eH3g9BFXVX6AURxLiUXzhNBUEZuj/OEyH9yEF
/qPCE+EjzVvWxvBXwgz/io4r4yok/Vq/bxJ6FlV6R7DX5oJSXyO0VEHZPi9DIyNU
kK3F/r4U1sWiJGWOs8i3YQWZ2ejh1C0aLFZpPcCGGgMNpoF31gyYP6ZuPDUyCXsE
g36UUw1JHNtIXYcLhnXuqj4A8TybTDpgXLqvwA9DBQIDAQABo1MwUTAdBgNVHQ4E
FgQUc13z30pFC63rr/HGKOE7E82vjXwwHwYDVR0jBBgwFoAUc13z30pFC63rr/HG
KOE7E82vjXwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAHO3j
oeiUXXJ7xD4P8Wj5t9d+E8lE1Xv1Dk3Z+EdG5+dan+RcToE42JJp9zB7FIh5Qz8g
W77LAjqh5oyqz3A2VJcyVgfE3uJP1R1mJM7JfGHf84QH4TZF2Q1RZY4SZs0VQ6+q
5wSlIZ4NXDy4Q4XkIJBGS61wT8IzYFXYBpx4PCP1Qj0PIE4sevEGwjsBIgxK307o
BxF8AWe6N6e4YZmQLGjQ+SeH0iwZb6vpkHyAY8Kj2hvK+cq2P7vU3VGi0t3r1F8L
IvrXHCvO2BMNJ/1UK1M4YNX8LYJqQhg9hEsIROe1OE/m3VhxIYMJI+qZXk9yHfgJ
vq+SH04xKhtFudVBAQ==`

	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "nil admin config",
			cfg: &Config{
				Admin: nil,
			},
			wantErr: false,
		},
		{
			name: "nil remote config",
			cfg: &Config{
				Admin: &AdminConfig{},
			},
			wantErr: false,
		},
		{
			name: "invalid listen address",
			cfg: &Config{
				Admin: &AdminConfig{
					Remote: &RemoteAdmin{
						Listen: "invalid:address",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: &Config{
				Admin: &AdminConfig{
					Identity: &IdentityConfig{},
					Remote: &RemoteAdmin{
						Listen: "localhost:2021",
						AccessControl: []*AdminAccess{
							{
								PublicKeys:  []string{testCert},
								Permissions: []AdminPermissions{{Methods: []string{"GET"}, Paths: []string{"/test"}}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid certificate",
			cfg: &Config{
				Admin: &AdminConfig{
					Identity: &IdentityConfig{},
					Remote: &RemoteAdmin{
						Listen: "localhost:2021",
						AccessControl: []*AdminAccess{
							{
								PublicKeys:  []string{"invalid-cert-data"},
								Permissions: []AdminPermissions{{Methods: []string{"GET"}, Paths: []string{"/test"}}},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := Context{
				Context: context.Background(),
				cfg:     test.cfg,
			}

			if test.cfg != nil {
				test.cfg.storage = &certmagic.FileStorage{Path: t.TempDir()}
			}

			if test.cfg != nil && test.cfg.Admin != nil && test.cfg.Admin.Identity != nil {
				identityCertCache = certmagic.NewCache(certmagic.CacheOptions{
					GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
						return &certmagic.Config{}, nil
					},
				})
			}

			err := replaceRemoteAdminServer(ctx, test.cfg)

			if test.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}

			// Clean up
			if remoteAdminServer != nil {
				_ = stopAdminServer(remoteAdminServer)
			}
		})
	}
}

type mockIssuer struct {
	configSet *certmagic.Config
}

func (m *mockIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return &certmagic.IssuedCertificate{
		Certificate: []byte(csr.Raw),
	}, nil
}

func (m *mockIssuer) SetConfig(cfg *certmagic.Config) {
	m.configSet = cfg
}

func (m *mockIssuer) IssuerKey() string {
	return "mock"
}

type mockIssuerModule struct {
	*mockIssuer
}

func (m *mockIssuerModule) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID: "tls.issuance.acme",
		New: func() Module {
			return &mockIssuerModule{mockIssuer: new(mockIssuer)}
		},
	}
}

func TestManageIdentity(t *testing.T) {
	originalModules := make(map[string]ModuleInfo)
	for k, v := range modules {
		originalModules[k] = v
	}
	defer func() {
		modules = originalModules
	}()

	RegisterModule(&mockIssuerModule{})

	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3lcub2pUwkjC
5GJQA2ZZfJJi6d1QHhEmkX9VxKYGp6gagZuRqJWy9TXP6++1ZzQQxqZLD0TkuxZ9
8i9Nz00000CCBjCCAQQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGgG
CCsGAQUFBwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5j
b20vb2NzcDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/
BAIwADAfBgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHREEEDAO
ggxtYWlsLmdvb2dsZTANBgkqhkiG9w0BAQUFAAOCAQEAMP6IWgNGZE8wP9TjFjSZ
3mmW3A1eIr0CuPwNZ2LJ5ZD1i70ojzcj4I9IdP5yPg9CAEV4hNASbM1LzfC7GmJE
tPzW5tRmpKVWZGRgTgZI8Hp/xZXMwLh9ZmXV4kESFAGj5G5FNvJyUV7R5Eh+7OZX
7G4jJ4ZGJh+5jzN9HdJJHQHGYNIYOzC7+HH9UMwCjX9vhQ4RjwFZJThS2Yb+y7pb
9yxTJZoXC6J0H5JpnZb7kZEJ+Xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-----`)

	keyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRS0LmTwUT0iwP
...
-----END PRIVATE KEY-----`)

	testStorage := certmagic.FileStorage{Path: t.TempDir()}
	err := testStorage.Store(context.Background(), "localhost/localhost.crt", certPEM)
	if err != nil {
		t.Fatal(err)
	}
	err = testStorage.Store(context.Background(), "localhost/localhost.key", keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		cfg        *Config
		wantErr    bool
		checkState func(*testing.T, *Config)
	}{
		{
			name: "nil config",
			cfg:  nil,
		},
		{
			name: "nil admin config",
			cfg: &Config{
				Admin: nil,
			},
		},
		{
			name: "nil identity config",
			cfg: &Config{
				Admin: &AdminConfig{},
			},
		},
		{
			name: "default issuer when none specified",
			cfg: &Config{
				Admin: &AdminConfig{
					Identity: &IdentityConfig{
						Identifiers: []string{"localhost"},
					},
				},
				storage: &testStorage,
			},
			checkState: func(t *testing.T, cfg *Config) {
				if len(cfg.Admin.Identity.issuers) == 0 {
					t.Error("Expected at least 1 issuer to be configured")
					return
				}
				if _, ok := cfg.Admin.Identity.issuers[0].(*mockIssuerModule); !ok {
					t.Error("Expected mock issuer to be configured")
				}
			},
		},
		{
			name: "custom issuer",
			cfg: &Config{
				Admin: &AdminConfig{
					Identity: &IdentityConfig{
						Identifiers: []string{"localhost"},
						IssuersRaw: []json.RawMessage{
							json.RawMessage(`{"module": "acme"}`),
						},
					},
				},
				storage: &certmagic.FileStorage{Path: "testdata"},
			},
			checkState: func(t *testing.T, cfg *Config) {
				if len(cfg.Admin.Identity.issuers) != 1 {
					t.Fatalf("Expected 1 issuer, got %d", len(cfg.Admin.Identity.issuers))
				}
				mockIss, ok := cfg.Admin.Identity.issuers[0].(*mockIssuerModule)
				if !ok {
					t.Fatal("Expected mock issuer")
				}
				if mockIss.configSet == nil {
					t.Error("Issuer config was not set")
				}
			},
		},
		{
			name: "invalid issuer module",
			cfg: &Config{
				Admin: &AdminConfig{
					Identity: &IdentityConfig{
						Identifiers: []string{"localhost"},
						IssuersRaw: []json.RawMessage{
							json.RawMessage(`{"module": "doesnt_exist"}`),
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if identityCertCache != nil {
				// Reset the cert cache before each test
				identityCertCache.Stop()
				identityCertCache = nil
			}

			ctx := Context{
				Context:         context.Background(),
				cfg:             test.cfg,
				moduleInstances: make(map[string][]Module),
			}

			err := manageIdentity(ctx, test.cfg)

			if test.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}

			if test.checkState != nil {
				test.checkState(t, test.cfg)
			}
		})
	}
}
