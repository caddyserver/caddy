package fileserver

import (
	"bytes"
	"encoding/json"
	"html/template"
	"testing"
)

// The following benchmarks represent a comparison between some
// optimized methods and their previous implementation.
//
// Benchmark the old BrowseWriteJSON implementation.
func BenchmarkOldBrowseWriteJSON(b *testing.B) {
	ofsrv := new(oldFileServer)
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
		ofsrv.browseWriteJSON(listing)
	}
}

// Benchmark the new BrowseWriteJSON implementation.
func BenchmarkNewBrowseWriteJSON(b *testing.B) {
	fsrv := new(FileServer)
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

// Benchmark the old BrowseWriteHTML implementation.
func BenchmarkOldBrowseWriteHTML(b *testing.B) {
	ofsrv := new(oldFileServer)
	ofsrv.Browse = &Browse{
		TemplateFile: "",
		template:     template.New("test"),
	}
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		ofsrv.browseWriteHTML(browseListing{})
	}
}

// Benchmark the new BrowseWriteHTML implementation.
func BenchmarkNewBrowseWriteHTML(b *testing.B) {
	fsrv := new(FileServer)
	fsrv.Browse = &Browse{
		TemplateFile: "",
		template:     template.New("test"),
	}
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		fsrv.browseWriteHTML(browseListing{})
	}
}

// oldFileServer is a copy of FileServer that implements the older
// version of the benchmarked methods, while the 'real' FileServer
// holds the newer methods. This should ensure a fair comparison.
type oldFileServer struct {
	Root       string   `json:"root,omitempty"`
	Hide       []string `json:"hide,omitempty"`
	IndexNames []string `json:"index_names,omitempty"`
	Browse     *Browse  `json:"browse,omitempty"`
}

// The old browseWriteJSON version.
func (ofsrv *oldFileServer) browseWriteJSON(listing browseListing) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(listing.Items)
	return buf, err
}

// The old browseWriteHTML version.
func (ofsrv *oldFileServer) browseWriteHTML(listing browseListing) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	err := ofsrv.Browse.template.Execute(buf, listing)
	return buf, err
}
