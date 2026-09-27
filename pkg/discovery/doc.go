// Package discovery is a minimal in-process service registry keyed by server
// name and concrete type, resolved by interface. Servers register their
// service implementations at start-up and handlers look them up by the
// interface they need, which decouples packages from concrete types.
//
// Usage:
//
//	d := discovery.New()
//	if err := d.Register("api", &userService{}); err != nil {
//		return err
//	}
//
//	var svc UserService // an interface type
//	if err := d.Find("api", &svc); err != nil { // "" matches any server
//		return err
//	}
//
//	var closer io.Closer
//	err := d.ForEach(&closer, func(key string) error { // key is "<server>/<type>"
//		return closer.Close()
//	})
//
// Register, Find, and ForEach may run concurrently. ForEach visits a snapshot
// of matching services, so callbacks may register more services without
// changing the current iteration. Callers must synchronize destination values
// shared between goroutines. When several registered services implement the
// requested interface, Find returns an arbitrary one.
package discovery
