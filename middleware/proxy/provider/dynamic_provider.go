package provider

// DynamicProvider represents a dynamic hosts provider.
type DynamicProvider interface {
	Provider
	// Watch creates a new Watcher.
	Watch() Watcher
}

// WatcherMsg is the message sent by Watcher when there is a
// change to a host.
type WatcherMsg struct {
	// Host is the affected host
	Host string
	// Remove is true if the host should be removed instead.
	Remove bool
}

// Watcher watches for changes in the store.
// Next blocks until a new host is available.
type Watcher interface {
	Next() (msg WatcherMsg, err error)
}
