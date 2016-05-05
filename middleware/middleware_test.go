package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIndexfile(t *testing.T) {
	tests := []struct {
		rootDir           http.FileSystem
		fpath             string
		indexFiles        []string
		shouldErr         bool
		expectedFilePath  string //retun value
		expectedBoolValue bool   //return value
	}{
		{
			http.Dir("./templates/testdata"),
			"/images/",
			[]string{"img.htm"},
			false,
			"/images/img.htm",
			true,
		},
	}
	for i, test := range tests {
		actualFilePath, actualBoolValue := IndexFile(test.rootDir, test.fpath, test.indexFiles)
		if actualBoolValue == true && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if actualBoolValue != true && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got %s", i, "Please Add a / at the end of fpath or the indexFiles doesnt exist")
		}
		if actualFilePath != test.expectedFilePath {
			t.Fatalf("Test %d expected returned filepath to be %s, but got %s ",
				i, test.expectedFilePath, actualFilePath)

		}
		if actualBoolValue != test.expectedBoolValue {
			t.Fatalf("Test %d expected returned bool value to be %v, but got %v ",
				i, test.expectedBoolValue, actualBoolValue)

		}
	}
}

func TestSetLastModified(t *testing.T) {
	nowTime := time.Now()

	// ovewrite the function to return reliable time
	originalGetCurrentTimeFunc := currentTime
	currentTime = func() time.Time {
		return nowTime
	}
	defer func() {
		currentTime = originalGetCurrentTimeFunc
	}()

	pastTime := nowTime.Truncate(1 * time.Hour)
	futureTime := nowTime.Add(1 * time.Hour)

	tests := []struct {
		inputModTime         time.Time
		expectedIsHeaderSet  bool
		expectedLastModified string
	}{
		{
			inputModTime:         pastTime,
			expectedIsHeaderSet:  true,
			expectedLastModified: pastTime.UTC().Format(http.TimeFormat),
		},
		{
			inputModTime:         nowTime,
			expectedIsHeaderSet:  true,
			expectedLastModified: nowTime.UTC().Format(http.TimeFormat),
		},
		{
			inputModTime:         futureTime,
			expectedIsHeaderSet:  true,
			expectedLastModified: nowTime.UTC().Format(http.TimeFormat),
		},
		{
			inputModTime:        time.Time{},
			expectedIsHeaderSet: false,
		},
	}

	for i, test := range tests {
		responseRecorder := httptest.NewRecorder()
		errorPrefix := fmt.Sprintf("Test [%d]: ", i)
		SetLastModifiedHeader(responseRecorder, test.inputModTime)
		actualLastModifiedHeader := responseRecorder.Header().Get("Last-Modified")

		if test.expectedIsHeaderSet && actualLastModifiedHeader == "" {
			t.Fatalf(errorPrefix + "Expected to find Last-Modified header, but found nothing")
		}

		if !test.expectedIsHeaderSet && actualLastModifiedHeader != "" {
			t.Fatalf(errorPrefix+"Did not expect to find Last-Modified header, but found one [%s].", actualLastModifiedHeader)
		}

		if test.expectedLastModified != actualLastModifiedHeader {
			t.Errorf(errorPrefix+"Expected Last-Modified content [%s], found [%s}", test.expectedLastModified, actualLastModifiedHeader)
		}
	}
}
