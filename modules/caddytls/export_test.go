package caddytls

// IsManaging returns true if the name is being managed by this TLS app.
// This is for testing purposes only.
func (t *TLS) IsManaging(name string) bool {
	t.serverNamesMu.Lock()
	defer t.serverNamesMu.Unlock()
	_, ok := t.managing[name]
	return ok
}
