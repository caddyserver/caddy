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
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

func init() {
	RegisterModule(router{})
}

type router []AdminRoute

// CaddyModule returns the Caddy module information.
func (router) CaddyModule() ModuleInfo {
	return ModuleInfo{
		Name: "admin.routers.dynamic_config",
		New: func() Module {
			return router{
				{
					Pattern: "/" + rawConfigKey + "/",
					Handler: http.HandlerFunc(handleConfig),
				},
				{
					Pattern: "/id/",
					Handler: http.HandlerFunc(handleConfigID),
				},
			}
		},
	}
}

func (r router) Routes() []AdminRoute { return r }

// handleConfig handles config changes or exports according to r.
// This function is safe for concurrent use.
func handleConfig(w http.ResponseWriter, r *http.Request) {
	rawCfgMu.Lock()
	defer rawCfgMu.Unlock()
	unsyncedHandleConfig(w, r)
}

// handleConfigID accesses the config through a user-assigned ID
// that is mapped to its full/expanded path in the JSON structure.
// It is the same as handleConfig except it replaces the ID in
// the request path with the full, expanded URL path.
// This function is safe for concurrent use.
func handleConfigID(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 || parts[2] == "" {
		http.Error(w, "request path is missing object ID", http.StatusBadRequest)
		return
	}
	id := parts[2]

	rawCfgMu.Lock()
	defer rawCfgMu.Unlock()

	// map the ID to the expanded path
	expanded, ok := rawCfgIndex[id]
	if !ok {
		http.Error(w, "unknown object ID: "+id, http.StatusBadRequest)
		return
	}

	// piece the full URL path back together
	parts = append([]string{expanded}, parts[3:]...)
	r.URL.Path = path.Join(parts...)

	unsyncedHandleConfig(w, r)
}

// configIndex recurisvely searches ptr for object fields named "@id"
// and maps that ID value to the full configPath in the index.
// This function is NOT safe for concurrent access; use rawCfgMu.
func configIndex(ptr interface{}, configPath string, index map[string]string) error {
	switch val := ptr.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if k == "@id" {
				switch idVal := v.(type) {
				case string:
					index[idVal] = configPath
				case float64: // all JSON numbers decode as float64
					index[fmt.Sprintf("%v", idVal)] = configPath
				default:
					return fmt.Errorf("%s: @id field must be a string or number", configPath)
				}
				delete(val, "@id") // field is no longer needed, and will break config if not removed
				continue
			}
			// traverse this object property recursively
			err := configIndex(val[k], path.Join(configPath, k), index)
			if err != nil {
				return err
			}
		}
	case []interface{}:
		// traverse each element of the array recursively
		for i := range val {
			err := configIndex(val[i], path.Join(configPath, strconv.Itoa(i)), index)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// unsycnedHandleConfig handles config accesses without a lock
// on rawCfgMu. This is NOT safe for concurrent use, so be sure
// to acquire a lock on rawCfgMu before calling this.
func unsyncedHandleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// perform the mutation with our decoded representation
	// (the map), which may change pointers deep within it
	err := mutateConfig(w, r)
	if err != nil {
		http.Error(w, "mutating config: "+err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodGet {
		// find any IDs in this config and index them
		idx := make(map[string]string)
		err = configIndex(rawCfg[rawConfigKey], "/config", idx)
		if err != nil {
			http.Error(w, "indexing config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// the mutation is complete, so encode the entire config as JSON
		newCfg, err := json.Marshal(rawCfg[rawConfigKey])
		if err != nil {
			http.Error(w, "encoding new config: "+err.Error(), http.StatusBadRequest)
			return
		}

		// if nothing changed, no need to do a whole reload unless the client forces it
		if r.Header.Get("Cache-Control") != "must-revalidate" && bytes.Equal(rawCfgJSON, newCfg) {
			log.Printf("[ADMIN][INFO] Config is unchanged")
			return
		}

		// load this new config; if it fails, we need to revert to
		// our old representation of caddy's actual config
		err = Load(bytes.NewReader(newCfg))
		if err != nil {
			// restore old config state to keep it consistent
			// with what caddy is still running; we need to
			// unmarshal it again because it's likely that
			// pointers deep in our rawCfg map were modified
			var oldCfg interface{}
			err2 := json.Unmarshal(rawCfgJSON, &oldCfg)
			if err2 != nil {
				err = fmt.Errorf("%v; additionally, restoring old config: %v", err, err2)
			}
			rawCfg[rawConfigKey] = oldCfg

			// report error
			log.Printf("[ADMIN][ERROR] loading config: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// success, so update our stored copy of the encoded
		// config to keep it consistent with what caddy is now
		// running (storing an encoded copy is not strictly
		// necessary, but avoids an extra json.Marshal for
		// each config change)
		rawCfgJSON = newCfg
		rawCfgIndex = idx
	}
}

// mutateConfig changes the rawCfg according to r. It is NOT
// safe for concurrent use; use rawCfgMu. If the request's
// method is GET, the config will not be changed.
func mutateConfig(w http.ResponseWriter, r *http.Request) error {
	var err error
	var val interface{}

	// if there is a request body, make sure we recognize its content-type and decode it
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "/json") {
			return fmt.Errorf("unacceptable content-type: %v; 'application/json' required", ct)
		}
		err = json.NewDecoder(r.Body).Decode(&val)
		if err != nil {
			return fmt.Errorf("decoding request body: %v", err)
		}
	}

	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)

	cleanPath := strings.Trim(r.URL.Path, "/")
	if cleanPath == "" {
		return fmt.Errorf("no traversable path")
	}

	parts := strings.Split(cleanPath, "/")
	if len(parts) == 0 {
		return fmt.Errorf("path missing")
	}

	var ptr interface{} = rawCfg

traverseLoop:
	for i, part := range parts {
		switch v := ptr.(type) {
		case map[string]interface{}:
			// if the next part enters a slice, and the slice is our destination,
			// handle it specially (because appending to the slice copies the slice
			// header, which does not replace the original one like we want)
			if arr, ok := v[part].([]interface{}); ok && i == len(parts)-2 {
				var idx int
				if r.Method != http.MethodPost {
					idxStr := parts[len(parts)-1]
					idx, err = strconv.Atoi(idxStr)
					if err != nil {
						return fmt.Errorf("[%s] invalid array index '%s': %v",
							r.URL.Path, idxStr, err)
					}
					if idx < 0 || idx >= len(arr) {
						return fmt.Errorf("[%s] array index out of bounds: %s", r.URL.Path, idxStr)
					}
				}

				switch r.Method {
				case http.MethodGet:
					err = enc.Encode(arr[idx])
					if err != nil {
						return fmt.Errorf("encoding config: %v", err)
					}
				case http.MethodPost:
					v[part] = append(arr, val)
				case http.MethodPut:
					// avoid creation of new slice and a second copy (see
					// https://github.com/golang/go/wiki/SliceTricks#insert)
					arr = append(arr, nil)
					copy(arr[idx+1:], arr[idx:])
					arr[idx] = val
					v[part] = arr
				case http.MethodPatch:
					arr[idx] = val
				case http.MethodDelete:
					v[part] = append(arr[:idx], arr[idx+1:]...)
				default:
					return fmt.Errorf("unrecognized method %s", r.Method)
				}
				break traverseLoop
			}

			if i == len(parts)-1 {
				switch r.Method {
				case http.MethodGet:
					err = enc.Encode(v[part])
					if err != nil {
						return fmt.Errorf("encoding config: %v", err)
					}
				case http.MethodPost:
					if arr, ok := v[part].([]interface{}); ok {
						// if the part is an existing list, POST appends to it
						// TODO: Do we ever reach this point, since we handle arrays
						// separately above?
						v[part] = append(arr, val)
					} else {
						// otherwise, it simply sets the value
						v[part] = val
					}
				case http.MethodPut:
					if _, ok := v[part]; ok {
						return fmt.Errorf("[%s] key already exists: %s", r.URL.Path, part)
					}
					v[part] = val
				case http.MethodPatch:
					if _, ok := v[part]; !ok {
						return fmt.Errorf("[%s] key does not exist: %s", r.URL.Path, part)
					}
					v[part] = val
				case http.MethodDelete:
					delete(v, part)
				default:
					return fmt.Errorf("unrecognized method %s", r.Method)
				}
			} else {
				ptr = v[part]
			}

		case []interface{}:
			partInt, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("[/%s] invalid array index '%s': %v",
					strings.Join(parts[:i+1], "/"), part, err)
			}
			if partInt < 0 || partInt >= len(v) {
				return fmt.Errorf("[/%s] array index out of bounds: %s",
					strings.Join(parts[:i+1], "/"), part)
			}
			ptr = v[partInt]

		default:
			return fmt.Errorf("invalid path: %s", parts[:i+1])
		}
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf.Bytes())
	}

	return nil
}

var (
	// rawCfg is the current, generic-decoded configuration;
	// we initialize it as a map with one field ("config")
	// to maintain parity with the API endpoint and to avoid
	// the special case of having to access/mutate the variable
	// directly without traversing into it
	rawCfg = map[string]interface{}{
		rawConfigKey: nil,
	}
	rawCfgJSON  []byte            // keeping the encoded form avoids an extra Marshal on changes
	rawCfgIndex map[string]string // map of user-assigned ID to expanded path
	rawCfgMu    sync.Mutex        // protects rawCfg, rawCfgJSON, and rawCfgIndex
)

const rawConfigKey = "config"
