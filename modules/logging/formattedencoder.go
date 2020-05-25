package logging

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(FormattedEncoder{})
}

const commonLogFormat = `{http.common_log}`

// FormattedEncoder allows the user to provide custom template for log prints. The
// encoder builds atop the json encoder, thus it follows its message structure. The placeholders
// are namespaced by the name of the app logging the message.
type FormattedEncoder struct {
	zapcore.Encoder `json:"-"`
	LogEncoderConfig
	Template string `json:"template,omitempty"`
}

func (FormattedEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.logging.encoders.formatted",
		New: func() caddy.Module {
			return &FormattedEncoder{
				Encoder: new(JSONEncoder),
			}
		},
	}
}

// Provision sets up the encoder.
func (se *FormattedEncoder) Provision(ctx caddy.Context) error {
	if se.Template == "" {
		return fmt.Errorf("missing template for formatted log encoder")
	}
	se.Encoder = zapcore.NewJSONEncoder(se.ZapcoreEncoderConfig())
	return nil
}

// Clone wraps the underlying encoder's Clone. This is
// necessary because we implement our own EncodeEntry,
// and if we simply let the embedded encoder's Clone
// be promoted, it would return a clone of that, and
// we'd lose our FormattedEncoder's EncodeEntry.
func (se FormattedEncoder) Clone() zapcore.Encoder {
	return FormattedEncoder{
		Encoder:  se.Encoder.Clone(),
		Template: se.Template,
	}
}

// EncodeEntry partially implements the zapcore.Encoder interface.
func (se FormattedEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	repl := caddy.NewReplacer()
	buf, err := se.Encoder.EncodeEntry(ent, fields)
	if err != nil {
		return buf, err
	}
	appName := strings.SplitN(ent.LoggerName, ".", 2)[0]
	// set the vals in the replacer
	err = jsonparser.ObjectEach(buf.Bytes(), visitor(appName, repl))
	buf.Reset() // the buffer is only used to collect placeholders' values anyway
	if err != nil {
		return buf, err
	}

	out := repl.ReplaceKnown(se.Template, "")
	// Unescape escaped quotes
	buf.AppendString(strings.Replace(out, `\"`, `"`, -1))
	if !strings.HasSuffix(out, "\n") {
		buf.AppendByte('\n')
	}
	return buf, err
}

func visitor(prefix string, repl *caddy.Replacer) func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
	format := fmt.Sprintf("%s.%%s", prefix)
	keyFormat := func(itemKey string) string {
		return fmt.Sprintf(format, itemKey)
	}
	return func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		switch dataType {
		case jsonparser.NotExist:
			panic("unimplemented jsonparser visitor for NotExist")
		case jsonparser.String:
			repl.Set(keyFormat(string(key)), string(value))
		case jsonparser.Number:
			// see: https://github.com/buger/jsonparser/issues/85
			if bytes.IndexByte(value, '.') > -1 {
				v, _ := strconv.ParseFloat(string(value), 64)
				repl.Set(keyFormat(string(key)), v)
			} else {
				v, _ := strconv.ParseUint(string(value), 10, 64)
				repl.Set(keyFormat(string(key)), v)
			}
		case jsonparser.Object:
			// recurse
			err := jsonparser.ObjectEach(value, visitor(keyFormat(string(key)), repl))
			if err != nil {
				return err
			}
		case jsonparser.Array:
			repl.Set(keyFormat(string(key)), value)
		case jsonparser.Boolean:
			v, _ := strconv.ParseBool(string(value))
			repl.Set(keyFormat(string(key)), v)
		case jsonparser.Null:
			panic("unimplemented jsonparser visitor for Null")
		case jsonparser.Unknown:
			panic("unimplemented jsonparser visitor for Unknown")
		default:
			panic("completely unknown dataType")
		}
		return nil
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//     formatted <template>
//
// If the value of "template" is omitted, Common Log Format is assumed.
// See the godoc on the LogEncoderConfig type for the syntax of
// subdirectives that are common to most/all encoders.
func (se *FormattedEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var template string
		if !d.AllArgs(&template) {
			template = commonLogFormat
		}
		se.Template = template
	}
	return nil
}
