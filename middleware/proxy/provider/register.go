package provider

func init() {
	// static
	Register("http", newStatic)
	Register("https", newStatic)
	Register("", newStatic)

	// dynamic
	Register("etcd", newDynamic)
	Register("consul", newDynamic)
	Register("zk", newDynamic)
}
