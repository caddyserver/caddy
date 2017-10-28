// Copyright 2015 Light Code Labs, LLC
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

package log

import (
	"net"
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `log`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	cfg := httpserver.GetConfig(c)
	mids := cfg.Middleware()
	if mids == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Logger)

	if !ok {
		t.Fatalf("Expected handler to be type Logger, got: %#v", handler)
	}

	if myHandler.Rules[0].PathScope != "/" {
		t.Errorf("Expected / as the default PathScope")
	}

	expectedLogger := &httpserver.Logger{
		Output:   DefaultLogFilename,
		Roller:   httpserver.DefaultLogRoller(),
		V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
		V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
	}

	if !reflect.DeepEqual(myHandler.Rules[0].Entries[0].Log, expectedLogger) {
		t.Errorf("Expected %v as the default Log, got: %v", expectedLogger, myHandler.Rules[0].Entries[0].Log)
	}
	if myHandler.Rules[0].Entries[0].Format != DefaultLogFormat {
		t.Errorf("Expected %s as the default Log Format", DefaultLogFormat)
	}
	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestLogParse(t *testing.T) {
	tests := []struct {
		inputLogRules    string
		shouldErr        bool
		expectedLogRules []Rule
	}{
		{`log`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   DefaultLogFilename,
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: DefaultLogFormat,
			}},
		}}},
		{`log log.txt`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "log.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: DefaultLogFormat,
			}},
		}}},
		{`log syslog://127.0.0.1:5000`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "syslog://127.0.0.1:5000",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: DefaultLogFormat,
			}},
		}}},
		{`log syslog+tcp://127.0.0.1:5000`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "syslog+tcp://127.0.0.1:5000",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: DefaultLogFormat,
			}},
		}}},
		{`log /api log.txt`, false, []Rule{{
			PathScope: "/api",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "log.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: DefaultLogFormat,
			}},
		}}},
		{`log /serve stdout`, false, []Rule{{
			PathScope: "/serve",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "stdout",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: DefaultLogFormat,
			}},
		}}},
		{`log /myapi log.txt {common}`, false, []Rule{{
			PathScope: "/myapi",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "log.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: CommonLogFormat,
			}},
		}}},
		{`log /myapi log.txt "prefix {common} suffix"`, false, []Rule{{
			PathScope: "/myapi",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "log.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: "prefix " + CommonLogFormat + " suffix",
			}},
		}}},
		{`log /test accesslog.txt {combined}`, false, []Rule{{
			PathScope: "/test",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "accesslog.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: CombinedLogFormat,
			}},
		}}},
		{`log /test accesslog.txt "prefix {combined} suffix"`, false, []Rule{{
			PathScope: "/test",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "accesslog.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: "prefix " + CombinedLogFormat + " suffix",
			}},
		}}},
		{`log /api1 log.txt
		  log /api2 accesslog.txt {combined}`, false, []Rule{{
			PathScope: "/api1",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "log.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: DefaultLogFormat,
			}},
		}, {
			PathScope: "/api2",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "accesslog.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: CombinedLogFormat,
			}},
		}}},
		{`log /api3 stdout {host}
		  log /api4 log.txt {when}`, false, []Rule{{
			PathScope: "/api3",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "stdout",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: "{host}",
			}},
		}, {
			PathScope: "/api4",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "log.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: "{when}",
			}},
		}}},
		{`log access.log {
			rotate_size 2
			rotate_age 10
			rotate_keep 3
			rotate_compress
		}`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output: "access.log",
					Roller: &httpserver.LogRoller{
						MaxSize:    2,
						MaxAge:     10,
						MaxBackups: 3,
						Compress:   true,
						LocalTime:  true,
					},
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},

				Format: DefaultLogFormat,
			}},
		}}},
		{`log access0.log {
			ipmask 255.255.255.0
		}`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:       "access0.log",
					Roller:       httpserver.DefaultLogRoller(),
					V4ipMask:     net.IPMask(net.ParseIP("255.255.255.0").To4()),
					V6ipMask:     net.IPMask(net.ParseIP(DefaultIP6Mask)),
					IPMaskExists: true,
				},

				Format: DefaultLogFormat,
			}},
		}}},
		{`log access1.log {
			ipmask "" ffff:ffff:ffff:ff00::
		}`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:       "access1.log",
					Roller:       httpserver.DefaultLogRoller(),
					V4ipMask:     net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask:     net.IPMask(net.ParseIP("ffff:ffff:ffff:ff00::")),
					IPMaskExists: true,
				},

				Format: DefaultLogFormat,
			}},
		}}},
		{`log access2.log {
			ipmask 255.255.255.0 ffff:ffff:ffff:ff00::
		}`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:       "access2.log",
					Roller:       httpserver.DefaultLogRoller(),
					V4ipMask:     net.IPMask(net.ParseIP("255.255.255.0").To4()),
					V6ipMask:     net.IPMask(net.ParseIP("ffff:ffff:ffff:ff00::")),
					IPMaskExists: true,
				},

				Format: DefaultLogFormat,
			}},
		}}},
		{`log / stdout {host}
		  log / log.txt {when}`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{
					Output:   "stdout",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: "{host}",
			}, {
				Log: &httpserver.Logger{
					Output:   "log.txt",
					Roller:   httpserver.DefaultLogRoller(),
					V4ipMask: net.IPMask(net.ParseIP(DefaultIP4Mask).To4()),
					V6ipMask: net.IPMask(net.ParseIP(DefaultIP6Mask)),
				},
				Format: "{when}",
			}},
		}}},
		{`log access.log { rotate_size 2 rotate_age 10 rotate_keep 3 }`, true, nil},
		{`log access.log { rotate_compress invalid }`, true, nil},
		{`log access.log { rotate_size }`, true, nil},
		{`log access.log { ipmask }`, true, nil},
		{`log access.log { invalid_option 1 }`, true, nil},
		{`log / acccess.log "{remote} - [{when}] "{method} {port}" {scheme} {mitm} "`, true, nil},
	}
	for i, test := range tests {
		c := caddy.NewTestController("http", test.inputLogRules)
		actualLogRules, err := logParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if len(actualLogRules) != len(test.expectedLogRules) {
			t.Fatalf("Test %d expected %d no of Log rules, but got %d ",
				i, len(test.expectedLogRules), len(actualLogRules))
		}
		for j, actualLogRule := range actualLogRules {

			if actualLogRule.PathScope != test.expectedLogRules[j].PathScope {
				t.Errorf("Test %d expected %dth LogRule PathScope to be  %s  , but got %s",
					i, j, test.expectedLogRules[j].PathScope, actualLogRule.PathScope)
			}

			if got, expect := len(actualLogRule.Entries), len(test.expectedLogRules[j].Entries); got != expect {
				t.Fatalf("Test %d expected %dth LogRule with %d no of Log entries, but got %d ",
					i, j, expect, got)
			}

			for k, actualEntry := range actualLogRule.Entries {
				if !reflect.DeepEqual(actualEntry.Log, test.expectedLogRules[j].Entries[k].Log) {
					t.Errorf("Test %d expected %dth LogRule Log to be  %v  , but got %v",
						i, j, test.expectedLogRules[j].Entries[k].Log, actualEntry.Log)
				}

				if actualEntry.Format != test.expectedLogRules[j].Entries[k].Format {
					t.Errorf("Test %d expected %dth LogRule Format to be  %s  , but got %s",
						i, j, test.expectedLogRules[j].Entries[k].Format, actualEntry.Format)
				}
			}
		}
	}
}
