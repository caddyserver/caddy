package browse

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"text/template"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

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

func TestBrowseHTTPMethods(t *testing.T) {
	tmpl, err := template.ParseFiles("testdata/photos.tpl")
	if err != nil {
		t.Fatalf("An error occured while parsing the template: %v", err)
	}

	b := Browse{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return http.StatusTeapot, nil // not t.Fatalf, or we will not see what other methods yield
		}),
		Configs: []Config{
			{
				PathScope: "/photos",
				Root:      http.Dir("./testdata"),
				Template:  tmpl,
			},
		},
	}

	rec := httptest.NewRecorder()
	for method, expected := range map[string]int{
		http.MethodGet:     http.StatusOK,
		http.MethodHead:    http.StatusOK,
		http.MethodOptions: http.StatusNotImplemented,
		"PROPFIND":         http.StatusNotImplemented,
	} {
		req, err := http.NewRequest(method, "/photos/", nil)
		if err != nil {
			t.Fatalf("Test: Could not create HTTP request: %v", err)
		}

		code, _ := b.ServeHTTP(rec, req)
		if code != expected {
			t.Errorf("Wrong status with HTTP Method %s: expected %d, got %d", method, expected, code)
		}
	}
}

func TestBrowseTemplate(t *testing.T) {
	tmpl, err := template.ParseFiles("testdata/photos.tpl")
	if err != nil {
		t.Fatalf("An error occured while parsing the template: %v", err)
	}

	b := Browse{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatalf("Next shouldn't be called")
			return 0, nil
		}),
		Configs: []Config{
			{
				PathScope: "/photos",
				Root:      http.Dir("./testdata"),
				Template:  tmpl,
			},
		},
	}

	req, err := http.NewRequest("GET", "/photos/", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}

	rec := httptest.NewRecorder()

	code, _ := b.ServeHTTP(rec, req)
	if code != http.StatusOK {
		t.Fatalf("Wrong status, expected %d, got %d", http.StatusOK, code)
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

<a href="./test.html">test.html</a><br>

<a href="./test2.html">test2.html</a><br>

<a href="./test3.html">test3.html</a><br>

</body>
</html>
`

	if respBody != expectedBody {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}

}

func TestBrowseJson(t *testing.T) {
	b := Browse{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatalf("Next shouldn't be called")
			return 0, nil
		}),
		Configs: []Config{
			{
				PathScope: "/photos/",
				Root:      http.Dir("./testdata"),
			},
		},
	}

	//Getting the listing from the ./testdata/photos, the listing returned will be used to validate test results
	testDataPath := filepath.Join("./testdata", "photos")
	file, err := os.Open(testDataPath)
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

	for i, f := range files {
		name := f.Name()

		// Tests fail in CI environment because all file mod times are the same for
		// some reason, making the sorting unpredictable. To hack around this,
		// we ensure here that each file has a different mod time.
		chTime := f.ModTime().UTC().Add(-(time.Duration(i) * time.Second))
		if err := os.Chtimes(filepath.Join(testDataPath, name), chTime, chTime); err != nil {
			t.Fatal(err)
		}

		if f.IsDir() {
			name += "/"
		}

		url := url.URL{Path: "./" + name}

		fileinfos = append(fileinfos, FileInfo{
			IsDir:   f.IsDir(),
			Name:    f.Name(),
			Size:    f.Size(),
			URL:     url.String(),
			ModTime: chTime,
			Mode:    f.Mode(),
		})
	}
	listing := Listing{Items: fileinfos} // this listing will be used for validation inside the tests

	tests := []struct {
		QueryURL       string
		SortBy         string
		OrderBy        string
		Limit          int
		shouldErr      bool
		expectedResult []FileInfo
	}{
		//test case 1: testing for default sort and  order and without the limit parameter, default sort is by name and the default order is ascending
		//without the limit query entire listing will be produced
		{"/", "", "", -1, false, listing.Items},
		//test case 2: limit is set to 1, orderBy and sortBy is default
		{"/?limit=1", "", "", 1, false, listing.Items[:1]},
		//test case 3 : if the listing request is bigger than total size of listing then it should return everything
		{"/?limit=100000000", "", "", 100000000, false, listing.Items},
		//test case 4 : testing for negative limit
		{"/?limit=-1", "", "", -1, false, listing.Items},
		//test case 5 : testing with limit set to -1 and order set to descending
		{"/?limit=-1&order=desc", "", "desc", -1, false, listing.Items},
		//test case 6 : testing with limit set to 2 and order set to descending
		{"/?limit=2&order=desc", "", "desc", 2, false, listing.Items},
		//test case 7 : testing with limit set to 3 and order set to descending
		{"/?limit=3&order=desc", "", "desc", 3, false, listing.Items},
		//test case 8 : testing with limit set to 3 and order set to ascending
		{"/?limit=3&order=asc", "", "asc", 3, false, listing.Items},
		//test case 9 : testing with limit set to 1111111 and order set to ascending
		{"/?limit=1111111&order=asc", "", "asc", 1111111, false, listing.Items},
		//test case 10 : testing with limit set to default and order set to ascending and sorting by size
		{"/?order=asc&sort=size", "size", "asc", -1, false, listing.Items},
		//test case 11 : testing with limit set to default and order set to ascending and sorting by last modified
		{"/?order=asc&sort=time", "time", "asc", -1, false, listing.Items},
		//test case 12 : testing with limit set to 1 and order set to ascending and sorting by last modified
		{"/?order=asc&sort=time&limit=1", "time", "asc", 1, false, listing.Items},
		//test case 13 : testing with limit set to -100 and order set to ascending and sorting by last modified
		{"/?order=asc&sort=time&limit=-100", "time", "asc", -100, false, listing.Items},
		//test case 14 : testing with limit set to -100 and order set to ascending and sorting by size
		{"/?order=asc&sort=size&limit=-100", "size", "asc", -100, false, listing.Items},
	}

	for i, test := range tests {
		var marsh []byte
		req, err := http.NewRequest("GET", "/photos"+test.QueryURL, nil)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}

		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()

		code, err := b.ServeHTTP(rec, req)

		if code != http.StatusOK {
			t.Fatalf("In test %d: Wrong status, expected %d, got %d", i, http.StatusOK, code)
		}
		if rec.HeaderMap.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("Expected Content type to be application/json; charset=utf-8, but got %s ", rec.HeaderMap.Get("Content-Type"))
		}

		actualJSONResponse := rec.Body.String()
		copyOflisting := listing
		if test.SortBy == "" {
			copyOflisting.Sort = "name"
		} else {
			copyOflisting.Sort = test.SortBy
		}
		if test.OrderBy == "" {
			copyOflisting.Order = "asc"
		} else {
			copyOflisting.Order = test.OrderBy
		}

		copyOflisting.applySort()

		limit := test.Limit
		if limit <= len(copyOflisting.Items) && limit > 0 {
			marsh, err = json.Marshal(copyOflisting.Items[:limit])
		} else { // if the 'limit' query is empty, or has the wrong value, list everything
			marsh, err = json.Marshal(copyOflisting.Items)
		}

		if err != nil {
			t.Fatalf("Unable to Marshal the listing ")
		}
		expectedJSON := string(marsh)

		if actualJSONResponse != expectedJSON {
			t.Errorf("JSON response doesn't match the expected for test number %d with sort=%s, order=%s\nExpected response %s\nActual response = %s\n",
				i+1, test.SortBy, test.OrderBy, expectedJSON, actualJSONResponse)
		}
	}
}

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
