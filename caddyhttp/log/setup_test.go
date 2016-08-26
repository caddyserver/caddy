package log

import (
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
	if myHandler.Rules[0].Entries[0].OutputFile != DefaultLogFilename {
		t.Errorf("Expected %s as the default OutputFile", DefaultLogFilename)
	}
	if myHandler.Rules[0].Entries[0].Format != DefaultLogFormat {
		t.Errorf("Expected %s as the default Log Format", DefaultLogFormat)
	}
	if myHandler.Rules[0].Entries[0].Roller != nil {
		t.Errorf("Expected Roller to be nil, got: %v",
			*myHandler.Rules[0].Entries[0].Roller)
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
				OutputFile: DefaultLogFilename,
				Format:     DefaultLogFormat,
			}},
		}}},
		{`log log.txt`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				OutputFile: "log.txt",
				Format:     DefaultLogFormat,
			}},
		}}},
		{`log /api log.txt`, false, []Rule{{
			PathScope: "/api",
			Entries: []*Entry{{
				OutputFile: "log.txt",
				Format:     DefaultLogFormat,
			}},
		}}},
		{`log /serve stdout`, false, []Rule{{
			PathScope: "/serve",
			Entries: []*Entry{{
				OutputFile: "stdout",
				Format:     DefaultLogFormat,
			}},
		}}},
		{`log /myapi log.txt {common}`, false, []Rule{{
			PathScope: "/myapi",
			Entries: []*Entry{{
				OutputFile: "log.txt",
				Format:     CommonLogFormat,
			}},
		}}},
		{`log /test accesslog.txt {combined}`, false, []Rule{{
			PathScope: "/test",
			Entries: []*Entry{{
				OutputFile: "accesslog.txt",
				Format:     CombinedLogFormat,
			}},
		}}},
		{`log /api1 log.txt
		  log /api2 accesslog.txt {combined}`, false, []Rule{{
			PathScope: "/api1",
			Entries: []*Entry{{
				OutputFile: "log.txt",
				Format:     DefaultLogFormat,
			}},
		}, {
			PathScope: "/api2",
			Entries: []*Entry{{
				OutputFile: "accesslog.txt",
				Format:     CombinedLogFormat,
			}},
		}}},
		{`log /api3 stdout {host}
		  log /api4 log.txt {when}`, false, []Rule{{
			PathScope: "/api3",
			Entries: []*Entry{{
				OutputFile: "stdout",
				Format:     "{host}",
			}},
		}, {
			PathScope: "/api4",
			Entries: []*Entry{{
				OutputFile: "log.txt",
				Format:     "{when}",
			}},
		}}},
		{`log access.log { rotate { size 2 age 10 keep 3 } }`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				OutputFile: "access.log",
				Format:     DefaultLogFormat,
				Roller: &httpserver.LogRoller{
					MaxSize:    2,
					MaxAge:     10,
					MaxBackups: 3,
					LocalTime:  true,
				},
			}},
		}}},
		{`log / stdout {host}
		  log / log.txt {when}`, false, []Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				OutputFile: "stdout",
				Format:     "{host}",
			}, {
				OutputFile: "log.txt",
				Format:     "{when}",
			}},
		}}},
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
				if actualEntry.OutputFile != test.expectedLogRules[j].Entries[k].OutputFile {
					t.Errorf("Test %d expected %dth LogRule OutputFile to be  %s  , but got %s",
						i, j, test.expectedLogRules[j].Entries[k].OutputFile, actualEntry.OutputFile)
				}

				if actualEntry.Format != test.expectedLogRules[j].Entries[k].Format {
					t.Errorf("Test %d expected %dth LogRule Format to be  %s  , but got %s",
						i, j, test.expectedLogRules[j].Entries[k].Format, actualEntry.Format)
				}
				if actualEntry.Roller != nil && test.expectedLogRules[j].Entries[k].Roller == nil || actualEntry.Roller == nil && test.expectedLogRules[j].Entries[k].Roller != nil {
					t.Fatalf("Test %d expected %dth LogRule Roller to be %v, but got %v",
						i, j, test.expectedLogRules[j].Entries[k].Roller, actualEntry.Roller)
				}
				if actualEntry.Roller != nil && test.expectedLogRules[j].Entries[k].Roller != nil {
					if actualEntry.Roller.Filename != test.expectedLogRules[j].Entries[k].Roller.Filename {
						t.Fatalf("Test %d expected %dth LogRule Roller Filename to be %s, but got %s",
							i, j, test.expectedLogRules[j].Entries[k].Roller.Filename, actualEntry.Roller.Filename)
					}
					if actualEntry.Roller.MaxAge != test.expectedLogRules[j].Entries[k].Roller.MaxAge {
						t.Fatalf("Test %d expected %dth LogRule Roller MaxAge to be %d, but got %d",
							i, j, test.expectedLogRules[j].Entries[k].Roller.MaxAge, actualEntry.Roller.MaxAge)
					}
					if actualEntry.Roller.MaxBackups != test.expectedLogRules[j].Entries[k].Roller.MaxBackups {
						t.Fatalf("Test %d expected %dth LogRule Roller MaxBackups to be %d, but got %d",
							i, j, test.expectedLogRules[j].Entries[k].Roller.MaxBackups, actualEntry.Roller.MaxBackups)
					}
					if actualEntry.Roller.MaxSize != test.expectedLogRules[j].Entries[k].Roller.MaxSize {
						t.Fatalf("Test %d expected %dth LogRule Roller MaxSize to be %d, but got %d",
							i, j, test.expectedLogRules[j].Entries[k].Roller.MaxSize, actualEntry.Roller.MaxSize)
					}
					if actualEntry.Roller.LocalTime != test.expectedLogRules[j].Entries[k].Roller.LocalTime {
						t.Fatalf("Test %d expected %dth LogRule Roller LocalTime to be %t, but got %t",
							i, j, test.expectedLogRules[j].Entries[k].Roller.LocalTime, actualEntry.Roller.LocalTime)
					}
				}
			}
		}
	}

}
