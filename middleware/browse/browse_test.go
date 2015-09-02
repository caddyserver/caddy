package browse

import (
        "encoding/json"
	"github.com/mholt/caddy/middleware"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"testing"
	"text/template"
	"time"
)

// "sort" package has "IsSorted" function, but no "IsReversed";
func isReversed(data sort.Interface) bool {
	n := data.Len()
	for i := n - 1; i > 0; i-- {
		if !data.Less(i, i-1) {
			return false
		}
	}
	return true
}

func TestSort(t *testing.T) {
	// making up []fileInfo with bogus values;
	// to be used to make up our "listing"
	fileInfos := []FileInfo{
		{
			Name:    "fizz",
			Size:    4,
			ModTime: time.Now().AddDate(-1, 1, 0),
		},
		{
			Name:    "buzz",
			Size:    2,
			ModTime: time.Now().AddDate(0, -3, 3),
		},
		{
			Name:    "bazz",
			Size:    1,
			ModTime: time.Now().AddDate(0, -2, -23),
		},
		{
			Name:    "jazz",
			Size:    3,
			ModTime: time.Now(),
		},
	}
	listing := Listing{
		Name:    "foobar",
		Path:    "/fizz/buzz",
		CanGoUp: false,
		Items:   fileInfos,
	}

	// sort by name
	listing.Sort = "name"
	listing.applySort()
	if !sort.IsSorted(byName(listing)) {
		t.Errorf("The listing isn't name sorted: %v", listing.Items)
	}

	// sort by size
	listing.Sort = "size"
	listing.applySort()
	if !sort.IsSorted(bySize(listing)) {
		t.Errorf("The listing isn't size sorted: %v", listing.Items)
	}

	// sort by Time
	listing.Sort = "time"
	listing.applySort()
	if !sort.IsSorted(byTime(listing)) {
		t.Errorf("The listing isn't time sorted: %v", listing.Items)
	}

	// reverse by name
	listing.Sort = "name"
	listing.Order = "desc"
	listing.applySort()
	if !isReversed(byName(listing)) {
		t.Errorf("The listing isn't reversed by name: %v", listing.Items)
	}

	// reverse by size
	listing.Sort = "size"
	listing.Order = "desc"
	listing.applySort()
	if !isReversed(bySize(listing)) {
		t.Errorf("The listing isn't reversed by size: %v", listing.Items)
	}

	// reverse by time
	listing.Sort = "time"
	listing.Order = "desc"
	listing.applySort()
	if !isReversed(byTime(listing)) {
		t.Errorf("The listing isn't reversed by time: %v", listing.Items)
	}
}

func TestBrowseTemplate(t *testing.T) {
	tmpl, err := template.ParseFiles("testdata/photos.tpl")
	if err != nil {
		t.Fatalf("An error occured while parsing the template: %v", err)
	}

	b := Browse{
		Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatalf("Next shouldn't be called")
			return 0, nil
		}),
		Root: "./testdata",
		Configs: []Config{
			Config{
				PathScope: "/photos",
				Template:  tmpl,
			},
		},
	}

	req, err := http.NewRequest("GET", "/photos/", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}

	rec := httptest.NewRecorder()

	b.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Wrong status, expected %d, got %d", http.StatusOK, rec.Code)
	}

	respBody := rec.Body.String()
	expectedBody := `<!DOCTYPE html>
<html>
<head>
<title>Template</title>
</head>
<body>
<h1>Header</h1>

<h1>/photos/</h1>

<a href="test.html">test.html</a><br>

<a href="test2.html">test2.html</a><br>

</body>
</html>
`

	if respBody != expectedBody {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}

}

func TestBrowseJson(t *testing.T) {

	b := Browse{
		Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatalf("Next shouldn't be called")
			return 0, nil
		}),
		Root: "./testdata",
		Configs: []Config{
			Config{
				PathScope: "/photos",
			},
		},
	}

	req, err := http.NewRequest("GET", "/photos/", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	b.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Wrong status, expected %d, got %d", http.StatusOK, rec.Code)
	}
	if rec.HeaderMap.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("Expected Content type to be application/json; charset=utf-8, but got %s ", rec.HeaderMap.Get("Content-Type"))
	}

	actualJsonResponseString := rec.Body.String()

	//generating the listing to compare it with the response body
	file, err := os.Open(b.Root + req.URL.Path)
	if err != nil {
		if os.IsPermission(err) {
			t.Fatalf("Os Permission Error")

		}

	}
	defer file.Close()

	files, err := file.Readdir(-1)
	if err != nil {
		t.Fatalf("Unable to Read Contents of the directory")
	}
	var fileinfos []FileInfo
	for _, f := range files {
		name := f.Name()

		if f.IsDir() {
			name += "/"
		}

		url := url.URL{Path: name}

		fileinfos = append(fileinfos, FileInfo{
			IsDir:   f.IsDir(),
			Name:    f.Name(),
			Size:    f.Size(),
			URL:     url.String(),
			ModTime: f.ModTime(),
			Mode:    f.Mode(),
		})
	}
	listing := Listing{
		Items: fileinfos,
	}
	listing.Sort = "name"
	listing.Order = "asc"
	listing.applySort()

	marsh, err := json.Marshal(listing.Items)
	if err != nil {
		t.Fatalf("Unable to Marshal the listing ")
	}
	expectedJsonString := string(marsh)
	if actualJsonResponseString != expectedJsonString {
		t.Errorf("Json response string doesnt match the expected Json response ")
	}
}
