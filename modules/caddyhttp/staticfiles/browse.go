package staticfiles

import (
	"net/http"
)

// Browse configures directory browsing.
type Browse struct {
}

// ServeHTTP determines if the request is for this plugin, and if all prerequisites are met.
// If so, control is handed over to ServeListing.
func (b Browse) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	// TODO: convert this handler
	return nil

	// // Browse works on existing directories; delegate everything else
	// requestedFilepath, err := bc.Fs.Root.Open(r.URL.Path)
	// if err != nil {
	// 	switch {
	// 	case os.IsPermission(err):
	// 		return http.StatusForbidden, err
	// 	case os.IsExist(err):
	// 		return http.StatusNotFound, err
	// 	default:
	// 		return b.Next.ServeHTTP(w, r)
	// 	}
	// }
	// defer requestedFilepath.Close()

	// info, err := requestedFilepath.Stat()
	// if err != nil {
	// 	switch {
	// 	case os.IsPermission(err):
	// 		return http.StatusForbidden, err
	// 	case os.IsExist(err):
	// 		return http.StatusGone, err
	// 	default:
	// 		return b.Next.ServeHTTP(w, r)
	// 	}
	// }
	// if !info.IsDir() {
	// 	return b.Next.ServeHTTP(w, r)
	// }

	// // Do not reply to anything else because it might be nonsensical
	// switch r.Method {
	// case http.MethodGet, http.MethodHead:
	// 	// proceed, noop
	// case "PROPFIND", http.MethodOptions:
	// 	return http.StatusNotImplemented, nil
	// default:
	// 	return b.Next.ServeHTTP(w, r)
	// }

	// // Browsing navigation gets messed up if browsing a directory
	// // that doesn't end in "/" (which it should, anyway)
	// u := *r.URL
	// if u.Path == "" {
	// 	u.Path = "/"
	// }
	// if u.Path[len(u.Path)-1] != '/' {
	// 	u.Path += "/"
	// 	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	// 	return http.StatusMovedPermanently, nil
	// }

	// return b.ServeListing(w, r, requestedFilepath, bc)
}

// func (b Browse) loadDirectoryContents(requestedFilepath http.File, urlPath string, config *Config) (*Listing, bool, error) {
// 	files, err := requestedFilepath.Readdir(-1)
// 	if err != nil {
// 		return nil, false, err
// 	}

// 	// Determine if user can browse up another folder
// 	var canGoUp bool
// 	curPathDir := path.Dir(strings.TrimSuffix(urlPath, "/"))
// 	for _, other := range b.Configs {
// 		if strings.HasPrefix(curPathDir, other.PathScope) {
// 			canGoUp = true
// 			break
// 		}
// 	}

// 	// Assemble listing of directory contents
// 	listing, hasIndex := directoryListing(files, canGoUp, urlPath, config)

// 	return &listing, hasIndex, nil
// }

// // handleSortOrder gets and stores for a Listing the 'sort' and 'order',
// // and reads 'limit' if given. The latter is 0 if not given.
// //
// // This sets Cookies.
// func (b Browse) handleSortOrder(w http.ResponseWriter, r *http.Request, scope string) (sort string, order string, limit int, err error) {
// 	sort, order, limitQuery := r.URL.Query().Get("sort"), r.URL.Query().Get("order"), r.URL.Query().Get("limit")

// 	// If the query 'sort' or 'order' is empty, use defaults or any values previously saved in Cookies
// 	switch sort {
// 	case "":
// 		sort = sortByNameDirFirst
// 		if sortCookie, sortErr := r.Cookie("sort"); sortErr == nil {
// 			sort = sortCookie.Value
// 		}
// 	case sortByName, sortByNameDirFirst, sortBySize, sortByTime:
// 		http.SetCookie(w, &http.Cookie{Name: "sort", Value: sort, Path: scope, Secure: r.TLS != nil})
// 	}

// 	switch order {
// 	case "":
// 		order = "asc"
// 		if orderCookie, orderErr := r.Cookie("order"); orderErr == nil {
// 			order = orderCookie.Value
// 		}
// 	case "asc", "desc":
// 		http.SetCookie(w, &http.Cookie{Name: "order", Value: order, Path: scope, Secure: r.TLS != nil})
// 	}

// 	if limitQuery != "" {
// 		limit, err = strconv.Atoi(limitQuery)
// 		if err != nil { // if the 'limit' query can't be interpreted as a number, return err
// 			return
// 		}
// 	}

// 	return
// }

// // ServeListing returns a formatted view of 'requestedFilepath' contents'.
// func (b Browse) ServeListing(w http.ResponseWriter, r *http.Request, requestedFilepath http.File, bc *Config) (int, error) {
// 	listing, containsIndex, err := b.loadDirectoryContents(requestedFilepath, r.URL.Path, bc)
// 	if err != nil {
// 		switch {
// 		case os.IsPermission(err):
// 			return http.StatusForbidden, err
// 		case os.IsExist(err):
// 			return http.StatusGone, err
// 		default:
// 			return http.StatusInternalServerError, err
// 		}
// 	}
// 	if containsIndex && !b.IgnoreIndexes { // directory isn't browsable
// 		return b.Next.ServeHTTP(w, r)
// 	}
// 	listing.Context = httpserver.Context{
// 		Root: bc.Fs.Root,
// 		Req:  r,
// 		URL:  r.URL,
// 	}
// 	listing.User = bc.Variables

// 	// Copy the query values into the Listing struct
// 	var limit int
// 	listing.Sort, listing.Order, limit, err = b.handleSortOrder(w, r, bc.PathScope)
// 	if err != nil {
// 		return http.StatusBadRequest, err
// 	}

// 	listing.applySort()

// 	if limit > 0 && limit <= len(listing.Items) {
// 		listing.Items = listing.Items[:limit]
// 		listing.ItemsLimitedTo = limit
// 	}

// 	var buf *bytes.Buffer
// 	acceptHeader := strings.ToLower(strings.Join(r.Header["Accept"], ","))
// 	switch {
// 	case strings.Contains(acceptHeader, "application/json"):
// 		if buf, err = b.formatAsJSON(listing, bc); err != nil {
// 			return http.StatusInternalServerError, err
// 		}
// 		w.Header().Set("Content-Type", "application/json; charset=utf-8")

// 	default: // There's no 'application/json' in the 'Accept' header; browse normally
// 		if buf, err = b.formatAsHTML(listing, bc); err != nil {
// 			return http.StatusInternalServerError, err
// 		}
// 		w.Header().Set("Content-Type", "text/html; charset=utf-8")

// 	}

// 	_, _ = buf.WriteTo(w)

// 	return http.StatusOK, nil
// }

// func (b Browse) formatAsJSON(listing *Listing, bc *Config) (*bytes.Buffer, error) {
// 	marsh, err := json.Marshal(listing.Items)
// 	if err != nil {
// 		return nil, err
// 	}

// 	buf := new(bytes.Buffer)
// 	_, err = buf.Write(marsh)
// 	return buf, err
// }

// func (b Browse) formatAsHTML(listing *Listing, bc *Config) (*bytes.Buffer, error) {
// 	buf := new(bytes.Buffer)
// 	err := bc.Template.Execute(buf, listing)
// 	return buf, err
// }
