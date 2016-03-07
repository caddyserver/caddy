package setup

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mholt/caddy/middleware/browse"
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

	for i, test := range []struct {
		input             string
		expectedPathScope []string
		shouldErr         bool
	}{
		// test case #0 tests handling of multiple pathscopes
		{"browse " + tempDirPath + "\n browse .", []string{tempDirPath, "."}, false},

		// test case #1 tests instantiation of browse.Config with default values
		{"browse /", []string{"/"}, false},

		// test case #2 tests detectaction of custom template
		{"browse . " + tempTemplatePath, []string{"."}, false},

		// test case #3 tests detection of non-existent template
		{"browse . " + nonExistantDirPath, nil, true},

		// test case #4 tests detection of duplicate pathscopes
		{"browse " + tempDirPath + "\n browse " + tempDirPath, nil, true},
	} {

		recievedFunc, err := Browse(NewTestController(test.input))
		if err != nil && !test.shouldErr {
			t.Errorf("Test case #%d recieved an error of %v", i, err)
		}
		if test.expectedPathScope == nil {
			continue
		}
		recievedConfigs := recievedFunc(nil).(browse.Browse).Configs
		for j, config := range recievedConfigs {
			if config.PathScope != test.expectedPathScope[j] {
				t.Errorf("Test case #%d expected a pathscope of %v, but got %v", i, test.expectedPathScope, config.PathScope)
			}
		}
	}
}
