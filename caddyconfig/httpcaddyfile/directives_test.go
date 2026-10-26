package httpcaddyfile

import (
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestHostsFromKeys(t *testing.T) {
	for i, tc := range []struct {
		keys             []Address
		expectNormalMode []string
		expectLoggerMode []string
	}{
		{
			[]Address{
				{Original: "foo", Host: "foo"},
			},
			[]string{"foo"},
			[]string{"foo"},
		},
		{
			[]Address{
				{Original: "foo", Host: "foo"},
				{Original: "bar", Host: "bar"},
			},
			[]string{"bar", "foo"},
			[]string{"bar", "foo"},
		},
		{
			[]Address{
				{Original: ":2015", Port: "2015"},
			},
			[]string{},
			[]string{},
		},
		{
			[]Address{
				{Original: ":443", Port: "443"},
			},
			[]string{},
			[]string{},
		},
		{
			[]Address{
				{Original: "foo", Host: "foo"},
				{Original: ":2015", Port: "2015"},
			},
			[]string{},
			[]string{"foo"},
		},
		{
			[]Address{
				{Original: "example.com:2015", Host: "example.com", Port: "2015"},
			},
			[]string{"example.com"},
			[]string{"example.com:2015"},
		},
		{
			[]Address{
				{Original: "example.com:80", Host: "example.com", Port: "80"},
			},
			[]string{"example.com"},
			[]string{"example.com"},
		},
		{
			[]Address{
				{Original: "https://:2015/foo", Scheme: "https", Port: "2015", Path: "/foo"},
			},
			[]string{},
			[]string{},
		},
		{
			[]Address{
				{Original: "https://example.com:2015/foo", Scheme: "https", Host: "example.com", Port: "2015", Path: "/foo"},
			},
			[]string{"example.com"},
			[]string{"example.com:2015"},
		},
	} {
		sb := serverBlock{parsedKeys: tc.keys}

		// test in normal mode
		actual := sb.hostsFromKeys(false)
		sort.Strings(actual)
		if !reflect.DeepEqual(tc.expectNormalMode, actual) {
			t.Errorf("Test %d (loggerMode=false): Expected: %v Actual: %v", i, tc.expectNormalMode, actual)
		}

		// test in logger mode
		actual = sb.hostsFromKeys(true)
		sort.Strings(actual)
		if !reflect.DeepEqual(tc.expectLoggerMode, actual) {
			t.Errorf("Test %d (loggerMode=true): Expected: %v Actual: %v", i, tc.expectLoggerMode, actual)
		}
	}
}

// test_ordered_plugin stands in for a plugin directive in the tests below.
// it registers from init() like a real plugin would, which also keeps it to
// once per process, since registering twice panics.
func init() {
	RegisterHandlerDirective("test_ordered_plugin", func(h Helper) (caddyhttp.MiddlewareHandler, error) {
		h.Next()
		return caddyhttp.StaticError{StatusCode: "500"}, nil
	})
	RegisterDirectiveOrder("test_ordered_plugin", Before, "respond")
}

// caddyfiles shared by the directive order tests below. the handle block in
// orderTestPlain is there so that the subroute path gets covered too, not
// just the top level of the site block, and orderTestReordered moves respond
// ahead of root so it has to adapt to something different.
const (
	orderTestPlain = `:8080 {
	root * /srv
	handle /foo {
		respond 200
		root * /other
	}
}
`
	orderTestReordered = "{\n\torder respond first\n}\n" + orderTestPlain

	// covers every positional, since first and last build the new order in
	// their own way and last can append in place
	orderTestConcurrent = `{
	order redir before respond
	order vars after root
	order root first
	order respond last
}
:8080 {
	respond 200
}
`
)

// adaptCaddyfile adapts the given Caddyfile with a fresh options map.
func adaptCaddyfile(t *testing.T, input string) string {
	t.Helper()
	return adaptWithOptions(t, input, nil)
}

// adaptWithOptions adapts the given Caddyfile with the caller's options map.
func adaptWithOptions(t *testing.T, input string, options map[string]any) string {
	t.Helper()
	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	out, _, err := adapter.Adapt([]byte(input), options)
	if err != nil {
		t.Fatalf("adapting: %v", err)
	}
	return string(out)
}

// adaptConcurrently adapts a Caddyfile using the order global option from
// several goroutines at once. A non-nil options map is shared by all of
// them; nil gives each adaptation its own. Run with -race.
func adaptConcurrently(t *testing.T, options map[string]any) {
	t.Helper()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				adapter := caddyfile.Adapter{ServerType: ServerType{}}
				if _, _, err := adapter.Adapt([]byte(orderTestConcurrent), options); err != nil {
					t.Errorf("adapting concurrently: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// handlerComesFirst reports whether handler a appears before handler b in
// the adapted JSON.
func handlerComesFirst(adapted, a, b string) bool {
	ai := strings.Index(adapted, `"handler":"`+a+`"`)
	bi := strings.Index(adapted, `"handler":"`+b+`"`)
	return ai >= 0 && bi >= 0 && ai < bi
}

// TestAdaptDirectiveOrderIsolation makes sure the order global option only
// applies to the adaptation it was written in.
func TestAdaptDirectiveOrderIsolation(t *testing.T) {
	baseline := adaptCaddyfile(t, orderTestPlain)

	// this one moves respond to the front, so it has to produce something
	// different than the default order does
	if out := adaptCaddyfile(t, orderTestReordered); out == baseline {
		t.Fatal("the order option had no effect, so this test proves nothing")
	}

	if out := adaptCaddyfile(t, orderTestPlain); out != baseline {
		t.Errorf("order option leaked into the next adaptation:\nExpected: %s\nActual:   %s", baseline, out)
	}
}

// TestAdaptDirectiveOrderAfterError makes sure a failed adaptation leaves
// nothing behind for the next one.
func TestAdaptDirectiveOrderAfterError(t *testing.T) {
	baseline := adaptCaddyfile(t, orderTestPlain)

	const broken = `{
	order respond before not_a_directive
}
:8080 {
	respond 200
}
`
	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	if _, _, err := adapter.Adapt([]byte(broken), nil); err == nil {
		t.Fatal("expected an error for an order option pointing at an unknown directive")
	}

	if out := adaptCaddyfile(t, orderTestPlain); out != baseline {
		t.Errorf("failed adaptation left the order broken:\nExpected: %s\nActual:   %s", baseline, out)
	}
}

// TestAdaptDirectiveOrderWithReusedOptions makes sure that handing the same
// options map to one adaptation after another doesn't carry the first one's
// order into the second, and that the caller's map is left alone.
func TestAdaptDirectiveOrderWithReusedOptions(t *testing.T) {
	baseline := adaptCaddyfile(t, orderTestPlain)

	options := map[string]any{}

	if out := adaptWithOptions(t, orderTestReordered, options); out == baseline {
		t.Fatal("the order option had no effect, so this test proves nothing")
	}
	if out := adaptWithOptions(t, orderTestPlain, options); out != baseline {
		t.Errorf("reused options map carried the order into the next adaptation:\nExpected: %s\nActual:   %s", baseline, out)
	}
	if len(options) > 0 {
		t.Errorf("adapting wrote into the caller's options map: %v", options)
	}

	// an order the caller put in the map itself is ignored as well, and the
	// slice behind it is never written to; if it were used here, root would
	// not be an ordered handler and adapting would fail
	callerOrder := []string{"respond"}
	options["order"] = callerOrder
	if out := adaptWithOptions(t, orderTestPlain, options); out != baseline {
		t.Errorf("an order from the caller's map was used:\nExpected: %s\nActual:   %s", baseline, out)
	}
	if !slices.Equal(callerOrder, []string{"respond"}) {
		t.Errorf("adapting modified the caller's order: %v", callerOrder)
	}
}

// TestConcurrentAdaptDirectiveOrder makes sure that adapting several
// Caddyfiles at once, all of them using the order global option, doesn't
// race or corrupt the order shared by the whole process.
// See https://github.com/caddyserver/caddy/issues/7994
func TestConcurrentAdaptDirectiveOrder(t *testing.T) {
	baseline := slices.Clone(directiveOrder)
	defaultBaseline := slices.Clone(defaultDirectiveOrder)

	adaptConcurrently(t, nil)

	if !slices.Equal(directiveOrder, baseline) {
		t.Errorf("adaptation changed the process-wide order:\nExpected: %v\nActual:   %v", baseline, directiveOrder)
	}
	if !slices.Equal(defaultDirectiveOrder, defaultBaseline) {
		t.Errorf("adaptation changed the default order:\nExpected: %v\nActual:   %v", defaultBaseline, defaultDirectiveOrder)
	}
}

// TestConcurrentAdaptDirectiveOrderWithReusedOptions is the same, except
// every goroutine is handed the same options map.
func TestConcurrentAdaptDirectiveOrderWithReusedOptions(t *testing.T) {
	baseline := slices.Clone(directiveOrder)
	defaultBaseline := slices.Clone(defaultDirectiveOrder)
	options := map[string]any{}

	adaptConcurrently(t, options)

	if !slices.Equal(directiveOrder, baseline) {
		t.Errorf("adaptation changed the process-wide order:\nExpected: %v\nActual:   %v", baseline, directiveOrder)
	}
	if !slices.Equal(defaultDirectiveOrder, defaultBaseline) {
		t.Errorf("adaptation changed the default order:\nExpected: %v\nActual:   %v", defaultBaseline, defaultDirectiveOrder)
	}
	if len(options) > 0 {
		t.Errorf("adapting wrote into the caller's options map: %v", options)
	}
}

// TestRegisterDirectiveOrderWithOrderOption makes sure an order registered
// by a plugin is still honored, and can still be overridden by the order
// global option without the override sticking around afterwards.
func TestRegisterDirectiveOrderWithOrderOption(t *testing.T) {
	if !slices.Contains(directiveOrder, "test_ordered_plugin") {
		t.Fatal("plugin directive was not added to the order")
	}
	if !slices.Contains(defaultDirectiveOrder, "respond") || slices.Contains(defaultDirectiveOrder, "test_ordered_plugin") {
		t.Errorf("registering a plugin order corrupted the default order: %v", defaultDirectiveOrder)
	}

	const site = `:8080 {
	respond 200
	test_ordered_plugin
}
`
	// with no order option, the registered position wins
	if out := adaptCaddyfile(t, site); !handlerComesFirst(out, "error", "static_response") {
		t.Errorf("expected the plugin directive before respond, got: %s", out)
	}

	// the order option overrides it
	overridden := adaptCaddyfile(t, "{\n\torder test_ordered_plugin after respond\n}\n"+site)
	if !handlerComesFirst(overridden, "static_response", "error") {
		t.Errorf("expected respond before the plugin directive, got: %s", overridden)
	}

	// and the override is gone again
	if out := adaptCaddyfile(t, site); !handlerComesFirst(out, "error", "static_response") {
		t.Errorf("the order option leaked past its own adaptation, got: %s", out)
	}
}
