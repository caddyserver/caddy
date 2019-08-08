package fileserver

import (
	"html/template"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func BenchmarkBrowseWriteJSON(b *testing.B) {
	fsrv := new(FileServer)
	fsrv.Provision(caddy.Context{})
	listing := browseListing{
		Name:           "test",
		Path:           "test",
		CanGoUp:        false,
		Items:          make([]fileInfo, 100),
		NumDirs:        42,
		NumFiles:       420,
		Sort:           "",
		Order:          "",
		ItemsLimitedTo: 42,
	}
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		fsrv.browseWriteJSON(listing)
	}
}

func BenchmarkBrowseWriteHTML(b *testing.B) {
	fsrv := new(FileServer)
	fsrv.Provision(caddy.Context{})
	fsrv.Browse = &Browse{
		TemplateFile: "",
		template:     template.New("test"),
	}
	listing := browseListing{
		Name:           "test",
		Path:           "test",
		CanGoUp:        false,
		Items:          make([]fileInfo, 100),
		NumDirs:        42,
		NumFiles:       420,
		Sort:           "",
		Order:          "",
		ItemsLimitedTo: 42,
	}
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		fsrv.browseWriteHTML(listing)
	}
}
