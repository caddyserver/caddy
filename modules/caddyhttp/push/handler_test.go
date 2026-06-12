package push

import (
	"testing"
)

func TestIsRemoteResource(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     bool
	}{
		{name: "http URL", resource: "http://example.com/style.css", want: true},
		{name: "https URL", resource: "https://example.com/script.js", want: true},
		{name: "protocol-relative", resource: "//cdn.example.com/lib.js", want: true},
		{name: "absolute path", resource: "/style.css", want: false},
		{name: "relative path", resource: "images/logo.png", want: false},
		{name: "empty string", resource: "", want: false},
		{name: "just slash", resource: "/", want: false},
		{name: "http in path", resource: "/http://example.com", want: false},
		{name: "single slash prefix", resource: "/script.js", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRemoteResource(tt.resource)
			if got != tt.want {
				t.Errorf("isRemoteResource(%q) = %v, want %v", tt.resource, got, tt.want)
			}
		})
	}
}

func TestParseLinkHeaderFormats(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantCount int
		wantURIs  []string
	}{
		{
			name:      "single link",
			header:    "</style.css>; rel=preload; as=style",
			wantCount: 1,
			wantURIs:  []string{"/style.css"},
		},
		{
			name:      "multiple links",
			header:    "</style.css>; as=style,</script.js>; as=script",
			wantCount: 2,
			wantURIs:  []string{"/style.css", "/script.js"},
		},
		{
			name:      "empty header",
			header:    "",
			wantCount: 0,
		},
		{
			name:      "no angle brackets",
			header:    "/style.css; rel=preload",
			wantCount: 0,
		},
		{
			name:      "link with nopush",
			header:    "</style.css>; rel=preload; nopush",
			wantCount: 1,
			wantURIs:  []string{"/style.css"},
		},
		{
			name:      "link with multiple params",
			header:    "</font.woff2>; rel=preload; as=font; crossorigin",
			wantCount: 1,
			wantURIs:  []string{"/font.woff2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := parseLinkHeader(tt.header)
			if len(resources) != tt.wantCount {
				t.Fatalf("parseLinkHeader(%q) returned %d resources, want %d", tt.header, len(resources), tt.wantCount)
			}
			for i, uri := range tt.wantURIs {
				if i >= len(resources) {
					break
				}
				if resources[i].uri != uri {
					t.Errorf("resources[%d].uri = %q, want %q", i, resources[i].uri, uri)
				}
			}
		})
	}
}

func TestParseLinkHeaderParams(t *testing.T) {
	resources := parseLinkHeader("</style.css>; rel=preload; as=style")
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	if r.params["rel"] != "preload" {
		t.Errorf("params['rel'] = %q, want 'preload'", r.params["rel"])
	}
	if r.params["as"] != "style" {
		t.Errorf("params['as'] = %q, want 'style'", r.params["as"])
	}
}

func TestParseLinkHeaderNopush(t *testing.T) {
	resources := parseLinkHeader("</style.css>; rel=preload; nopush")
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	if _, ok := r.params["nopush"]; !ok {
		t.Error("expected 'nopush' param to exist")
	}
}

func TestHandlerCaddyModule(t *testing.T) {
	h := Handler{}
	info := h.CaddyModule()
	if info.ID != "http.handlers.push" {
		t.Errorf("CaddyModule().ID = %v, want 'http.handlers.push'", info.ID)
	}
	if info.New == nil {
		t.Fatal("CaddyModule().New is nil")
	}
}
