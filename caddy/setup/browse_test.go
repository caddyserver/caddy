package setup

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mholt/caddy/caddy/parse"
	"github.com/mholt/caddy/middleware/browse"
	"github.com/mholt/caddy/server"
)

func TestBrowse(t *testing.T) {

	tempDirPath, err := getTempDirPath()
	if err != nil {
		t.Fatalf("BeforeTest: Failed to find an existing directory for testing! Error was: %v", err)
	}
	nonExistantDirPath := filepath.Join(tempDirPath, strconv.Itoa(int(time.Now().UnixNano())))

	tempTemplate, err := ioutil.TempFile(".", "tempTemplate")
	if err != nil {
		t.Fatalf("BeforeTest: Failed to create a temporary file in the working directory! Error was: %v", err)
	}
	defer os.Remove(tempTemplate.Name())

	tempTemplatePath := filepath.Join(".", tempTemplate.Name())

	testTokens := []string{
		"browse " + tempDirPath + "\n browse .",
		"browse /",
		"browse . " + tempTemplatePath,
		"browse . " + nonExistantDirPath,
		"browse " + tempDirPath + "\n browse " + tempDirPath,
	}

	tests := []struct {
		expectedPathScope []string
		shouldErr         bool
	}{
		// test case #0 tests handling of multiple pathscopes
		{[]string{tempDirPath, "."}, false},

		// test case #1 tests instantiation of browse.Config with default values
		{[]string{"/"}, false},

		// test case #2 tests detectaction of custom template
		{[]string{"."}, false},

		// test case #3 tests detection of non-existant template
		{nil, true},

		// test case #4 tests detection of duplicate pathscopes
		{nil, true},
	}

	for i, test := range tests {
		c := &Controller{Config: &server.Config{Root: "."}, Dispenser: parse.NewDispenser("", strings.NewReader(testTokens[i]))}
		retrievedFunc, err := Browse(c)
		if err != nil && !test.shouldErr {
			t.Errorf("Test case #%d recieved an error of %v", i, err)
		}
		if test.expectedPathScope == nil {
			continue
		}
		retrievedConfigs := retrievedFunc(nil).(browse.Browse).Configs
		for j, config := range retrievedConfigs {
			if config.PathScope != test.expectedPathScope[j] {
				t.Errorf("Test case #%d expected a pathscope of %v, but got %v", i, test.expectedPathScope, config.PathScope)
			}
		}
	}
}
