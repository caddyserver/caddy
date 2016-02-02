package provider

// staticProvider cater for static hardcoded hosts.
type staticProvider string

// Hosts satisfies Provider interface.
func (s staticProvider) Hosts() ([]string, error) {
	return []string{string(s)}, nil
}

// static creates a new static host provider.
func static(host string) (Provider, error) {
	return staticProvider(host), nil
}
