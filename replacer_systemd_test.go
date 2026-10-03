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
	"maps"
	"math"
	"slices"
	"strconv"
	"testing"
)

func TestParseSystemdListenFDs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pid     int
		env     map[string]string
		want    map[string][]int
		wantErr bool
	}{
		{
			name: "named descriptors including duplicates",
			pid:  42,
			env: map[string]string{
				"LISTEN_PID":     "42",
				"LISTEN_FDS":     "4",
				"LISTEN_FDNAMES": "web:dns:web:admin",
			},
			want: map[string][]int{
				"web":   {3, 5},
				"dns":   {4},
				"admin": {6},
			},
		},
		{name: "missing pid", pid: 42, env: map[string]string{}, wantErr: true},
		{name: "malformed pid", pid: 42, env: map[string]string{"LISTEN_PID": "x"}, wantErr: true},
		{name: "different pid", pid: 42, env: map[string]string{"LISTEN_PID": "41"}, wantErr: true},
		{name: "missing descriptor count", pid: 42, env: map[string]string{"LISTEN_PID": "42"}, wantErr: true},
		{name: "zero descriptors", pid: 42, env: map[string]string{"LISTEN_PID": "42", "LISTEN_FDS": "0"}, wantErr: true},
		{name: "negative descriptor count", pid: 42, env: map[string]string{"LISTEN_PID": "42", "LISTEN_FDS": "-1"}, wantErr: true},
		{name: "missing names", pid: 42, env: map[string]string{"LISTEN_PID": "42", "LISTEN_FDS": "1"}, wantErr: true},
		{name: "too few names", pid: 42, env: map[string]string{"LISTEN_PID": "42", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "web"}, wantErr: true},
		{name: "too many names", pid: 42, env: map[string]string{"LISTEN_PID": "42", "LISTEN_FDS": "1", "LISTEN_FDNAMES": "web:dns"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSystemdListenFDs(tc.pid, func(name string) (string, bool) {
				value, ok := tc.env[name]
				return value, ok
			})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !maps.EqualFunc(got, tc.want, slices.Equal) {
				t.Fatalf("descriptor mapping = %#v; want %#v", got, tc.want)
			}
		})
	}
}

func TestSystemdListenFDByName(t *testing.T) {
	descriptors := map[string][]int{
		"web": {3, 5},
		"dns": {4},
	}
	tooLargeIndex := "web:" + strconv.FormatUint(uint64(math.MaxInt)+1, 10)

	for _, tc := range []struct {
		input   string
		want    int
		wantErr bool
	}{
		{input: "web", want: 3},
		{input: "web:0", want: 3},
		{input: "web:1", want: 5},
		{input: "dns", want: 4},
		{input: "", wantErr: true},
		{input: "missing", wantErr: true},
		{input: "web:2", wantErr: true},
		{input: "web:-1", wantErr: true},
		{input: "web:+1", wantErr: true},
		{input: "web:0:extra", wantErr: true},
		{input: tooLargeIndex, wantErr: true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := systemdListenFDByName(descriptors, tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("descriptor = %d; want %d", got, tc.want)
			}
		})
	}
}
