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

package templates

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/dustin/go-humanize"
)

func TestHumanizeTimeLayouts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		format string
		input  string
		when   time.Time
	}{
		{
			name:   "default",
			format: "time",
			input:  "Sun, 02 Jan 2000 15:04:05 +0000",
			when:   time.Date(2000, time.January, 2, 15, 4, 5, 0, time.UTC),
		},
		{
			name:   "date only",
			format: "time:2006-Jan-02",
			input:  "2000-Jan-02",
			when:   time.Date(2000, time.January, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name:   "RFC3339",
			format: "time:" + time.RFC3339,
			input:  "2000-01-02T15:04:05Z",
			when:   time.Date(2000, time.January, 2, 15, 4, 5, 0, time.UTC),
		},
		{
			name:   "explicit default layout",
			format: "time:" + time.RFC1123Z,
			input:  "Sun, 02 Jan 2000 15:04:05 +0000",
			when:   time.Date(2000, time.January, 2, 15, 4, 5, 0, time.UTC),
		},
		{
			name:   "RFC3339 with time zone offset",
			format: "time:" + time.RFC3339,
			input:  "2000-01-02T17:34:05+02:30",
			when:   time.Date(2000, time.January, 2, 15, 4, 5, 0, time.UTC),
		},
		{
			name:   "custom date and time",
			format: "time:2006-01-02 15:04:05",
			input:  "2000-01-02 15:04:05",
			when:   time.Date(2000, time.January, 2, 15, 4, 5, 0, time.UTC),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := TemplateContext{}
			buf := bytes.NewBufferString(fmt.Sprintf("{{humanize %q %q}}", tc.format, tc.input))
			wantBefore := humanize.Time(tc.when)
			if err := c.executeTemplateInBuffer("test", buf); err != nil {
				t.Fatalf("rendering humanized time: %v", err)
			}
			wantAfter := humanize.Time(tc.when)
			if got := buf.String(); got != wantBefore && got != wantAfter {
				t.Errorf("expected %q or %q, got %q", wantBefore, wantAfter, got)
			}
		})
	}
}

func TestHumanizeInvalidTimeLayoutData(t *testing.T) {
	c := TemplateContext{}
	if _, err := c.funcHumanize("time:"+time.RFC3339, "not a timestamp"); err == nil {
		t.Fatal("expected invalid timestamp to return an error")
	}
}
