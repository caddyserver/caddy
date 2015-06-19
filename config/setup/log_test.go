package setup

import (
	"testing"

	caddylog "github.com/mholt/caddy/middleware/log"
)

func TestLog(t *testing.T) {

	c := newTestController(`log`)

	mid, err := Log(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(emptyNext)
	myHandler, ok := handler.(caddylog.Logger)

	if !ok {
		t.Fatalf("Expected handler to be type Ext, got: %#v", handler)
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
	if !sameNext(myHandler.Next, emptyNext) {
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
	}
	for i, test := range tests {
		c := newTestController(test.inputLogRules)
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
		}
	}

}
