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


func TestEnableClientCertificates(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	localhost {
       respond "hello from localhost"
       tls {
            clients {
                mode request 
                trusted_ca_certs MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ== 
            }
       }
	}
  `, "caddyfile", `{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":443"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"localhost"
									]
								}
							],
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"body": "hello from localhost",
													"handler": "static_response"
												}
											]
										}
									]
								}
							],
							"terminal": true
						}
					],
					"tls_connection_policies": [
						{
							"match": {
								"sni": [
									"localhost"
								]
							},
							"client_authentication": {
								"trusted_ca_certs": [
									"MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ=="
								],
								"mode": "request"
							}
						},
						{}
					]
				}
			}
		}
	}
}`)
}

func TestEnableClientCertificatesWithFile(t *testing.T) {

	caddytest.AssertAdapt(t, ` 
	localhost {
       respond "hello from localhost"
       tls {
            clients {
                mode request 
                trusted_ca_certs_file ../caddy.ca.cer
            }
       }
	}
  `, "caddyfile", `{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":443"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"localhost"
									]
								}
							],
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"body": "hello from localhost",
													"handler": "static_response"
												}
											]
										}
									]
								}
							],
							"terminal": true
						}
					],
					"tls_connection_policies": [
						{
							"match": {
								"sni": [
									"localhost"
								]
							},
							"client_authentication": {
								"trusted_ca_certs": [
									"MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ=="
								],
								"mode": "request"
							}
						},
						{}
					]
				}
			}
		}
	}
}`)
}