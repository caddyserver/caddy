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

package caddycmd

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
)

type storVal struct {
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`
}

// determineStorage returns the top-level storage module from the given config.
// It may return nil even if no error.
func determineStorage(configFile string, configAdapter string) (*storVal, error) {
	cfg, _, err := LoadConfig(configFile, configAdapter)
	if err != nil {
		return nil, err
	}

	// storage defaults to FileStorage if not explicitly
	// defined in the config, so the config can be valid
	// json but unmarshaling will fail.
	if !json.Valid(cfg) {
		return nil, &json.SyntaxError{}
	}
	var tmpStruct storVal
	err = json.Unmarshal(cfg, &tmpStruct)
	if err != nil {
		// default case, ignore the error
		var jsonError *json.SyntaxError
		if errors.As(err, &jsonError) {
			return nil, nil
		}
		return nil, err
	}

	return &tmpStruct, nil
}

func cmdImportStorage(fl Flags) (int, error) {
	importStorageCmdConfigFlag := fl.String("config")
	importStorageCmdImportFile := fl.String("input")

	if importStorageCmdConfigFlag == "" {
		return caddy.ExitCodeFailedStartup, errors.New("--config is required")
	}
	if importStorageCmdImportFile == "" {
		return caddy.ExitCodeFailedStartup, errors.New("--input is required")
	}

	// extract storage from config if possible
	storageCfg, err := determineStorage(importStorageCmdConfigFlag, "")
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// load specified storage or fallback to default
	var stor certmagic.Storage
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if storageCfg != nil && storageCfg.StorageRaw != nil {
		val, err := ctx.LoadModule(storageCfg, "StorageRaw")
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
		stor, err = val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
	} else {
		stor = caddy.DefaultStorage
	}

	// setup input
	var f *os.File
	if importStorageCmdImportFile == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(importStorageCmdImportFile)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("opening input file: %v", err)
		}
		defer f.Close()
	}

	// store each archive element
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return caddy.ExitCodeFailedQuit, fmt.Errorf("reading archive: %v", err)
		}

		b, err := io.ReadAll(tr)
		if err != nil {
			return caddy.ExitCodeFailedQuit, fmt.Errorf("reading archive: %v", err)
		}

		err = stor.Store(ctx, hdr.Name, b)
		if err != nil {
			return caddy.ExitCodeFailedQuit, fmt.Errorf("reading archive: %v", err)
		}
	}

	fmt.Println("Successfully imported storage")
	return caddy.ExitCodeSuccess, nil
}

func cmdExportStorage(fl Flags) (int, error) {
	exportStorageCmdConfigFlag := fl.String("config")
	exportStorageCmdOutputFlag := fl.String("output")

	if exportStorageCmdConfigFlag == "" {
		return caddy.ExitCodeFailedStartup, errors.New("--config is required")
	}
	if exportStorageCmdOutputFlag == "" {
		return caddy.ExitCodeFailedStartup, errors.New("--output is required")
	}

	// extract storage from config if possible
	storageCfg, err := determineStorage(exportStorageCmdConfigFlag, "")
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// load specified storage or fallback to default
	var stor certmagic.Storage
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if storageCfg != nil && storageCfg.StorageRaw != nil {
		val, err := ctx.LoadModule(storageCfg, "StorageRaw")
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
		stor, err = val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
	} else {
		stor = caddy.DefaultStorage
	}

	// enumerate all keys
	keys, err := stor.List(ctx, "", true)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// setup output
	var f *os.File
	if exportStorageCmdOutputFlag == "-" {
		f = os.Stdout
	} else {
		f, err = os.Create(exportStorageCmdOutputFlag)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("opening output file: %v", err)
		}
		defer f.Close()
	}

	// `IsTerminal: true` keys hold the values we
	// care about, write them out
	tw := tar.NewWriter(f)
	for _, k := range keys {
		info, err := stor.Stat(ctx, k)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				caddy.Log().Warn(fmt.Sprintf("key: %s removed while export is in-progress", k))
				continue
			}
			return caddy.ExitCodeFailedQuit, err
		}

		if info.IsTerminal {
			v, err := stor.Load(ctx, k)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					caddy.Log().Warn(fmt.Sprintf("key: %s removed while export is in-progress", k))
					continue
				}
				return caddy.ExitCodeFailedQuit, err
			}

			hdr := &tar.Header{
				Name:    k,
				Mode:    0o600,
				Size:    int64(len(v)),
				ModTime: info.Modified,
			}

			if err = tw.WriteHeader(hdr); err != nil {
				return caddy.ExitCodeFailedQuit, fmt.Errorf("writing archive: %v", err)
			}
			if _, err = tw.Write(v); err != nil {
				return caddy.ExitCodeFailedQuit, fmt.Errorf("writing archive: %v", err)
			}
		}
	}
	if err = tw.Close(); err != nil {
		return caddy.ExitCodeFailedQuit, fmt.Errorf("writing archive: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}
