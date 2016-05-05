package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware"
	caddylog "github.com/mholt/caddy/middleware/log"
)

func TestLog(t *testing.T) {

	c := NewTestController(`log`)

	mid, err := Log(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(caddylog.Logger)

	if !ok {
		t.Fatalf("Expected handler to be type Logger, got: %#v", handler)
	}

	if myHandler.Rules[0].PathScope != "/" {
		t.Errorf("Expected / as the default PathScope")
	}
	if myHandler.Rules[0].OutputFile != caddylog.DefaultLogFilename {
		t.Errorf("Expected %s as the default OutputFile", caddylog.DefaultLogFilename)
	}
	if myHandler.Rules[0].Format != caddylog.DefaultLogFormat {
		t.Errorf("Expected %s as the default Log Format", caddylog.DefaultLogFormat)
	}
	if myHandler.Rules[0].Roller != nil {
		t.Errorf("Expected Roller to be nil, got: %v", *myHandler.Rules[0].Roller)
	}
	if !SameNext(myHandler.Next, EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

}

func TestLogParse(t *testing.T) {
	tests := []struct {
		inputLogRules    string
		shouldErr        bool
		expectedLogRules []caddylog.Rule
	}{
		{`log`, false, []caddylog.Rule{{
			PathScope:  "/",
			OutputFile: caddylog.DefaultLogFilename,
			Format:     caddylog.DefaultLogFormat,
		}}},
		{`log log.txt`, false, []caddylog.Rule{{
			PathScope:  "/",
			OutputFile: "log.txt",
			Format:     caddylog.DefaultLogFormat,
		}}},
		{`log /api log.txt`, false, []caddylog.Rule{{
			PathScope:  "/api",
			OutputFile: "log.txt",
			Format:     caddylog.DefaultLogFormat,
		}}},
		{`log /serve stdout`, false, []caddylog.Rule{{
			PathScope:  "/serve",
			OutputFile: "stdout",
			Format:     caddylog.DefaultLogFormat,
		}}},
		{`log /myapi log.txt {common}`, false, []caddylog.Rule{{
			PathScope:  "/myapi",
			OutputFile: "log.txt",
			Format:     caddylog.CommonLogFormat,
		}}},
		{`log /test accesslog.txt {combined}`, false, []caddylog.Rule{{
			PathScope:  "/test",
			OutputFile: "accesslog.txt",
			Format:     caddylog.CombinedLogFormat,
		}}},
		{`log /api1 log.txt
		  log /api2 accesslog.txt {combined}`, false, []caddylog.Rule{{
			PathScope:  "/api1",
			OutputFile: "log.txt",
			Format:     caddylog.DefaultLogFormat,
		}, {
			PathScope:  "/api2",
			OutputFile: "accesslog.txt",
			Format:     caddylog.CombinedLogFormat,
		}}},
		{`log /api3 stdout {host}
		  log /api4 log.txt {when}`, false, []caddylog.Rule{{
			PathScope:  "/api3",
			OutputFile: "stdout",
			Format:     "{host}",
		}, {
			PathScope:  "/api4",
			OutputFile: "log.txt",
			Format:     "{when}",
		}}},
		{`log access.log { rotate { size 2 age 10 keep 3 } }`, false, []caddylog.Rule{{
			PathScope:  "/",
			OutputFile: "access.log",
			Format:     caddylog.DefaultLogFormat,
			Roller: &middleware.LogRoller{
				MaxSize:    2,
				MaxAge:     10,
				MaxBackups: 3,
				LocalTime:  true,
			},
		}}},
	}
	for i, test := range tests {
		c := NewTestController(test.inputLogRules)
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

			if actualLogRule.OutputFile != test.expectedLogRules[j].OutputFile {
				t.Errorf("Test %d expected %dth LogRule OutputFile to be  %s  , but got %s",
					i, j, test.expectedLogRules[j].OutputFile, actualLogRule.OutputFile)
			}

			if actualLogRule.Format != test.expectedLogRules[j].Format {
				t.Errorf("Test %d expected %dth LogRule Format to be  %s  , but got %s",
					i, j, test.expectedLogRules[j].Format, actualLogRule.Format)
			}
			if actualLogRule.Roller != nil && test.expectedLogRules[j].Roller == nil || actualLogRule.Roller == nil && test.expectedLogRules[j].Roller != nil {
				t.Fatalf("Test %d expected %dth LogRule Roller to be %v, but got %v",
					i, j, test.expectedLogRules[j].Roller, actualLogRule.Roller)
			}
			if actualLogRule.Roller != nil && test.expectedLogRules[j].Roller != nil {
				if actualLogRule.Roller.Filename != test.expectedLogRules[j].Roller.Filename {
					t.Fatalf("Test %d expected %dth LogRule Roller Filename to be %s, but got %s",
						i, j, test.expectedLogRules[j].Roller.Filename, actualLogRule.Roller.Filename)
				}
				if actualLogRule.Roller.MaxAge != test.expectedLogRules[j].Roller.MaxAge {
					t.Fatalf("Test %d expected %dth LogRule Roller MaxAge to be %d, but got %d",
						i, j, test.expectedLogRules[j].Roller.MaxAge, actualLogRule.Roller.MaxAge)
				}
				if actualLogRule.Roller.MaxBackups != test.expectedLogRules[j].Roller.MaxBackups {
					t.Fatalf("Test %d expected %dth LogRule Roller MaxBackups to be %d, but got %d",
						i, j, test.expectedLogRules[j].Roller.MaxBackups, actualLogRule.Roller.MaxBackups)
				}
				if actualLogRule.Roller.MaxSize != test.expectedLogRules[j].Roller.MaxSize {
					t.Fatalf("Test %d expected %dth LogRule Roller MaxSize to be %d, but got %d",
						i, j, test.expectedLogRules[j].Roller.MaxSize, actualLogRule.Roller.MaxSize)
				}
				if actualLogRule.Roller.LocalTime != test.expectedLogRules[j].Roller.LocalTime {
					t.Fatalf("Test %d expected %dth LogRule Roller LocalTime to be %t, but got %t",
						i, j, test.expectedLogRules[j].Roller.LocalTime, actualLogRule.Roller.LocalTime)
				}
			}
		}
	}

}
