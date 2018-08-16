package digestauth

import (
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
)

// Tear apart the Authorization header value.
// PAY ATTENTION: this is large and complicated relative to other ones I've seen
// based on Split() using ',', ' ', and '=' in various orders. It is also probably
// correct even if the realm contains a '=', ' ', or '"' character, or if the
// sender uses HT, CR, or LF in their whitespace.
//
// The map that comes back looks like { "qop": "auth", "ns":"00000001", etc... }
func parseAuthorization(auth *strings.Reader) (map[string]string, error) {
	parts := map[string]string{}

	skipLWS := func(r *strings.Reader) error {
		for {
			ch, err := r.ReadByte()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
				// its white, we skip it and stay in loop
			} else {
				if err := r.UnreadByte(); err != nil {
					return err
				}
				break
			}
		}
		return nil
	}

	readName := func(r *strings.Reader) (string, error) {
		name := []byte{}

		for {
			ch, err := r.ReadByte()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", err
			}

			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
				name = append(name, ch)
			} else {
				if err := r.UnreadByte(); err != nil {
					return "", err
				}
				break
			}
		}
		if len(name) == 0 {
			return "", fmt.Errorf("expected name, got didn't get one")
		}
		return string(name), nil
	}

	readValue := func(r *strings.Reader) (string, error) {
		ch, err := r.ReadByte()
		if err != nil {
			return "", err
		}

		if ch == '"' {
			v := []byte{}
			for {
				ch, err := r.ReadByte()
				if err != nil {
					return "", fmt.Errorf("premature end of value: %s", err.Error())
				}
				if ch == '\\' {
					ch2, err := r.ReadByte()
					if err != nil {
						return "", fmt.Errorf("premature end of value: %s", err.Error())
					}
					v = append(v, ch2)
				} else if ch == '"' {
					break
				} else {
					v = append(v, ch)
				}
			}
			return string(v), nil
		} else {
			r.UnreadByte()
			return readName(r) // handles unquoted values, like true/false in the "stale" paramter
		}
	}

	for {
		name, err := readName(auth)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if err := skipLWS(auth); err != nil {
			return nil, err
		}

		eq, err := auth.ReadByte()
		if err == io.EOF || eq != '=' {
			return nil, fmt.Errorf("Malformed %s parameter, no equals", name)
		}

		if err := skipLWS(auth); err != nil {
			return nil, err
		}

		val, err := readValue(auth)
		if err != nil {
			return nil, err
		}

		parts[name] = val

		comma, err := auth.ReadByte()
		if err == io.EOF {
			break // our exit
		}
		if err != nil {
			return nil, err
		}
		if comma != ',' {
			return nil, fmt.Errorf("expected comma, got %v", comma)
		}

		if err := skipLWS(auth); err != nil {
			if err == io.EOF {
				break // our exit, finding an EOF after a value and some whitespace
			}
			return nil, err
		}
	}

	if testing.Verbose() {
		log.Printf("auth header = %#v", parts)
	}

	return parts, nil
}
