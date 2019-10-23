package fileserver

import (
	"github.com/mholt/archiver/v3"
	"html/template"
	"reflect"
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

func TestFileServer_getArchiveWriter(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        interface{}
		wantErr     bool
	}{
		{name: "zip", contentType: "application/zip", want: new(archiver.Zip)},
		{name: "tar", contentType: "application/tar", want: new(archiver.Tar)},
		{name: "err", contentType: "application/wrong", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsrv := new(FileServer)
			got, err := fsrv.getArchiveWriter(tt.contentType)
			if (err != nil) != tt.wantErr {
				t.Errorf("getArchiveWriter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("getArchiveWriter() got = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("make sure all archives are implemented", func(y *testing.T) {
		fsrv := new(FileServer)
		for _, mimeType := range extensionToContentType {
			if _, err := fsrv.getArchiveWriter(mimeType); err != nil {
				t.Errorf("archive writer is for content type %v is not implemented yet: %v", mimeType, err)
			}
		}
	})
}

func Test_validateArchiveSelection(t *testing.T) {
	type args struct {
		extensions []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"zip", args{[]string{"zip"}}, false},
		{"xyz", args{[]string{"zip", "xyz"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateArchiveSelection(tt.args.extensions); (err != nil) != tt.wantErr {
				t.Errorf("validateArchiveSelection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateExtension(t *testing.T) {
	type args struct {
		extension string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"zip", args{"zip"}, false},
		{"tar", args{"tar"}, false},
		{"error", args{"ar"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateExtension(tt.args.extension); (err != nil) != tt.wantErr {
				t.Errorf("validateExtension() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
