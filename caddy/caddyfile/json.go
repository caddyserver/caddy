package caddyfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
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
		block := ServerBlock{Body: [][]interface{}{}}

		// Fill up host list
		for _, host := range sb.HostList() {
			block.Hosts = append(block.Hosts, standardizeScheme(host))
		}

		// Extract directives deterministically by sorting them
		var directives = make([]string, len(sb.Tokens))
		for dir := range sb.Tokens {
			directives = append(directives, dir)
		}
		sort.Strings(directives)

		// Convert each directive's tokens into our JSON structure
		for _, dir := range directives {
			disp := parse.NewDispenserTokens(filename, sb.Tokens[dir])
			for disp.Next() {
				block.Body = append(block.Body, constructLine(&disp))
			}
		}

		// tack this block onto the end of the list
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
func constructLine(d *parse.Dispenser) []interface{} {
	var args []interface{}

	args = append(args, d.Val())

	for d.NextArg() {
		if d.Val() == "{" {
			args = append(args, constructBlock(d))
			continue
		}
		args = append(args, d.Val())
	}

	return args
}

// constructBlock recursively processes tokens into a
// JSON-encodable structure. To be used in a directive's
// block. Goes to end of block.
func constructBlock(d *parse.Dispenser) [][]interface{} {
	block := [][]interface{}{}

	for d.Next() {
		if d.Val() == "}" {
			break
		}
		block = append(block, constructLine(d))
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

	for sbPos, sb := range j {
		if sbPos > 0 {
			result += "\n\n"
		}
		for i, host := range sb.Hosts {
			if i > 0 {
				result += ", "
			}
			result += standardizeScheme(host)
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
			result += `"` + strings.Replace(val, "\"", "\\\"", -1) + `"`
		} else {
			result += val
		}
	case int:
		result += strconv.Itoa(val)
	case float64:
		result += fmt.Sprintf("%v", val)
	case bool:
		result += fmt.Sprintf("%t", val)
	case [][]interface{}:
		result += " {\n"
		for _, arg := range val {
			result += strings.Repeat("\t", depth) + jsonToText(arg, depth+1) + "\n"
		}
		result += strings.Repeat("\t", depth-1) + "}"
	case []interface{}:
		for i, v := range val {
			if block, ok := v.([]interface{}); ok {
				result += "{\n"
				for _, arg := range block {
					result += strings.Repeat("\t", depth) + jsonToText(arg, depth+1) + "\n"
				}
				result += strings.Repeat("\t", depth-1) + "}"
				continue
			}
			result += jsonToText(v, depth)
			if i < len(val)-1 {
				result += " "
			}
		}
	}

	return result
}

// standardizeScheme turns an address like host:https into https://host,
// or "host:" into "host".
func standardizeScheme(addr string) string {
	if hostname, port, err := net.SplitHostPort(addr); err == nil {
		if port == "http" || port == "https" {
			addr = port + "://" + hostname
		}
	}
	return strings.TrimSuffix(addr, ":")
}

// Caddyfile encapsulates a slice of ServerBlocks.
type Caddyfile []ServerBlock

// ServerBlock represents a server block.
type ServerBlock struct {
	Hosts []string        `json:"hosts"`
	Body  [][]interface{} `json:"body"`
}
