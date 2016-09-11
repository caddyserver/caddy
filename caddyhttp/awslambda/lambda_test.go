package awslambda

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go/service/lambda"
)

func TestInvokeOK(t *testing.T) {
	replyPayload := `{ "name": "bob"}`
	invoker := &FakeInvoker{
		Calls: []*lambda.InvokeInput{},
		Reply: &lambda.InvokeOutput{
			Payload: []byte(replyPayload),
		},
	}
	h := initHandler(invoker)
	r, err := http.NewRequest("POST", "/lambda-test/foo", bytes.NewBufferString("hi"))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	status, err := h.ServeHTTP(w, r)
	if err != nil {
		t.Errorf("ServeHTTP returned err: %v", err)
	}
	if status != 200 {
		t.Errorf("Expected 200 status, got: %d", status)
	}

	if len(invoker.Calls) != 1 {
		t.Errorf("Expected 1 Invoke call, but got: %+v", invoker.Calls)
	}

	expected := replyPayload
	actual := w.Body.String()
	if expected != actual {
		t.Errorf("\nResponse body did not match\nExpected: %s\n  Actual: %s", expected, actual)
	}
}

func TestInvokeInvalidFunc(t *testing.T) {
	h := initHandler(nil)
	h.Configs[0].Include = []string{"blah"}
	r, err := http.NewRequest("POST", "/lambda-test/invalid", bytes.NewBufferString("hi"))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	status, err := h.ServeHTTP(w, r)
	if err != nil {
		t.Errorf("ServeHTTP returned err: %v", err)
	}
	if status != 202 {
		t.Errorf("Expected 202 status, got: %d", status)
	}
}

func TestParseFunction(t *testing.T) {
	for i, test := range []struct {
		path     string
		expected string
	}{
		{"/foo/bar", "bar"},
		{"/foo/bar/baz", "baz"},
		{"blah", "blah"},
		{"/foo/bar?a=b", "bar"},
		{"/foo/bar#anchor-here", "bar"},
		{"/foo/bar?a=/blah#anchor-here", "bar"},
	} {
		actual := ParseFunction(test.path)
		if actual != test.expected {
			t.Errorf("\nTest %d\nExpected: %s\n  Actual: %s", i, test.expected, actual)
		}
	}
}

////////////////////////////////////////

func marshalJSON(i interface{}) []byte {
	j, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	return j
}

func initHandler(invoker Invoker) Handler {
	return Handler{
		Next: &FakeHandler{ReplyStatus: 202},
		Configs: []*Config{
			&Config{
				Path:    "/lambda-test/",
				invoker: invoker,
			},
		},
	}
}

type FakeInvoker struct {
	Calls      []*lambda.InvokeInput
	Reply      *lambda.InvokeOutput
	ReplyError error
}

func (i *FakeInvoker) Invoke(input *lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	i.Calls = append(i.Calls, input)
	return i.Reply, i.ReplyError
}

type FakeHandler struct {
	ReplyStatus int
	ReplyError  error
	Calls       int
}

func (h *FakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	h.Calls += 1
	return h.ReplyStatus, h.ReplyError
}
