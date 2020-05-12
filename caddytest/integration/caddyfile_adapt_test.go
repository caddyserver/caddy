package integration

import (
	"io/ioutil"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfileAdaptToJSON(t *testing.T) {
	// load the list of test files from the dir
	files, err := ioutil.ReadDir("./caddyfile_adapt")
	if err != nil {
		t.Errorf("failed to read caddyfile_adapt dir: %s", err)
	}

	// prep a regexp to fix strings on windows
	winNewlines := regexp.MustCompile(`\r?\n`)

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		// read the test file
		filename := f.Name()
		data, err := ioutil.ReadFile("./caddyfile_adapt/" + filename)
		if err != nil {
			t.Errorf("failed to read %s dir: %s", filename, err)
		}

		// split the Caddyfile (first) and JSON (second) parts
		parts := strings.Split(string(data), "----------")
		caddyfile, json := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		// replace windows newlines in the json with unix newlines
		json = winNewlines.ReplaceAllString(json, "\n")

		// run the test
		ok := caddytest.CompareAdapt(t, caddyfile, "caddyfile", json)
		if !ok {
			t.Errorf("failed to adapt %s", filename)
		}
	}
}

func TestPhpFastCgiSubdirectives(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	:8884

	php_fastcgi localhost:9000 {
		# some php_fastcgi-specific subdirectives
		split .php .php5
		env VAR1 value1
		env VAR2 value2
		root /var/www
		index index.php5

		# passed through to reverse_proxy (directive order doesn't matter!)
		lb_policy random
	}	
  `, "caddyfile", `{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":8884"
					],
					"routes": [
						{
							"match": [
								{
									"file": {
										"try_files": [
											"{http.request.uri.path}/index.php5"
										]
									},
									"not": [
										{
											"path": [
												"*/"
											]
										}
									]
								}
							],
							"handle": [
								{
									"handler": "static_response",
									"headers": {
										"Location": [
											"{http.request.uri.path}/"
										]
									},
									"status_code": 308
								}
							]
						},
						{
							"match": [
								{
									"file": {
										"try_files": [
											"{http.request.uri.path}",
											"{http.request.uri.path}/index.php5",
											"index.php5"
										],
										"split_path": [
											".php",
											".php5"
										]
									}
								}
							],
							"handle": [
								{
									"handler": "rewrite",
									"uri": "{http.matchers.file.relative}"
								}
							]
						},
						{
							"match": [
								{
									"path": [
										"*.php",
										"*.php5"
									]
								}
							],
							"handle": [
								{
									"handler": "reverse_proxy",
									"load_balancing": {
										"selection_policy": {
											"policy": "random"
										}
									},
									"transport": {
										"env": {
											"VAR1": "value1",
											"VAR2": "value2"
										},
										"protocol": "fastcgi",
										"root": "/var/www",
										"split_path": [
											".php",
											".php5"
										]
									},
									"upstreams": [
										{
											"dial": "localhost:9000"
										}
									]
								}
							]
						}
					]
				}
			}
		}
	}
}`)
}

func TestPhpFastCgiSubdirectivesIndexOff(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	:8884

	php_fastcgi localhost:9000 {
		# some php_fastcgi-specific subdirectives
		split .php .php5
		env VAR1 value1
		env VAR2 value2
		root /var/www
		index off

		# passed through to reverse_proxy (directive order doesn't matter!)
		lb_policy random
	}	
  `, "caddyfile", `{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":8884"
					],
					"routes": [
						{
							"match": [
								{
									"path": [
										"*.php",
										"*.php5"
									]
								}
							],
							"handle": [
								{
									"handler": "reverse_proxy",
									"load_balancing": {
										"selection_policy": {
											"policy": "random"
										}
									},
									"transport": {
										"env": {
											"VAR1": "value1",
											"VAR2": "value2"
										},
										"protocol": "fastcgi",
										"root": "/var/www",
										"split_path": [
											".php",
											".php5"
										]
									},
									"upstreams": [
										{
											"dial": "localhost:9000"
										}
									]
								}
							]
						}
					]
				}
			}
		}
	}
}`)
}
