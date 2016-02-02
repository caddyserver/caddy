package provider

func init() {
	// static
	Register("http", static)
	Register("https", static)
	Register("", static)

	// dynamic
	Register("etcd", dynamic)
	Register("consul", dynamic)
	Register("zk", dynamic)
}
