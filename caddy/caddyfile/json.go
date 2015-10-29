package caddyfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mholt/caddy/caddy/parse"
)

const filename = "Caddyfile"

// ToJSON converts caddyfile to its JSON representation.
func ToJSON(caddyfile []byte) ([]byte, error) {
	var j Caddyfile

	serverBlocks, err := parse.ServerBlocks(filename, bytes.NewReader(caddyfile), false)
	if err != nil {
		return nil, err
	}

	for _, sb := range serverBlocks {
		block := ServerBlock{Body: make(map[string]interface{})}

		for _, host := range sb.HostList() {
			block.Hosts = append(block.Hosts, strings.TrimSuffix(host, ":"))
		}

		for dir, tokens := range sb.Tokens {
			disp := parse.NewDispenserTokens(filename, tokens)
			disp.Next() // the first token is the directive; skip it
			block.Body[dir] = constructLine(disp)
		}

		j = append(j, block)
	}

	result, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// constructLine transforms tokens into a JSON-encodable structure;
// but only one line at a time, to be used at the top-level of
// a server block only (where the first token on each line is a
// directive) - not to be used at any other nesting level.
func constructLine(d parse.Dispenser) interface{} {
	var args []interface{}

	all := d.RemainingArgs()
	for _, arg := range all {
		args = append(args, arg)
	}

	d.Next()
	if d.Val() == "{" {
		args = append(args, constructBlock(d))
	}

	return args
}

// constructBlock recursively processes tokens into a
// JSON-encodable structure.
func constructBlock(d parse.Dispenser) interface{} {
	block := make(map[string]interface{})

	for d.Next() {
		if d.Val() == "}" {
			break
		}

		dir := d.Val()
		all := d.RemainingArgs()

		var args []interface{}
		for _, arg := range all {
			args = append(args, arg)
		}
		if d.Val() == "{" {
			args = append(args, constructBlock(d))
		}

		block[dir] = args
	}

	return block
}

// FromJSON converts JSON-encoded jsonBytes to Caddyfile text
func FromJSON(jsonBytes []byte) ([]byte, error) {
	var j Caddyfile
	var result string

	err := json.Unmarshal(jsonBytes, &j)
	if err != nil {
		return nil, err
	}

	for _, sb := range j {
		for i, host := range sb.Hosts {
			if hostname, port, err := net.SplitHostPort(host); err == nil {
				if port == "http" || port == "https" {
					host = port + "://" + hostname
				}
			}
			if i > 0 {
				result += ", "
			}
			result += strings.TrimSuffix(host, ":")
		}
		result += jsonToText(sb.Body, 1)
	}

	return []byte(result), nil
}

// jsonToText recursively transforms a scope of JSON into plain
// Caddyfile text.
func jsonToText(scope interface{}, depth int) string {
	var result string

	switch val := scope.(type) {
	case string:
		if strings.ContainsAny(val, "\" \n\t\r") {
			result += ` "` + strings.Replace(val, "\"", "\\\"", -1) + `"`
		} else {
			result += " " + val
		}
	case int:
		result += " " + strconv.Itoa(val)
	case float64:
		result += " " + fmt.Sprintf("%v", val)
	case bool:
		result += " " + fmt.Sprintf("%t", val)
	case map[string]interface{}:
		result += " {\n"
		for param, args := range val {
			result += strings.Repeat("\t", depth) + param
			result += jsonToText(args, depth+1) + "\n"
		}
		result += strings.Repeat("\t", depth-1) + "}"
	case []interface{}:
		for _, v := range val {
			result += jsonToText(v, depth)
		}
	}

	return result
}

type Caddyfile []ServerBlock

type ServerBlock struct {
	Hosts []string               `json:"hosts"`
	Body  map[string]interface{} `json:"body"`
}
