package discovery

import (
	"fmt"
	"reflect"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "discovery")

// serviceInfo is a registry entry.
type serviceInfo struct {
	ServerName string
	Service    any
	Type       reflect.Type
}

// Discovery is an in-process registry of service implementations,
// resolved by the interface a caller needs. Not safe for concurrent
// modification; register everything before concurrent lookups.
type Discovery interface {
	// Register adds service under server; the key is "<server>/<concrete type>".
	// It returns an error if the same server/type pair is already registered.
	Register(server string, service any) error
	// Find sets *v (v must be a non-nil pointer to an interface) to a
	// registered service that implements that interface. server "" matches
	// any server. It returns an error if v is not a pointer to interface or
	// nothing matches.
	Find(server string, v any) error
	// ForEach sets *v to each registered service implementing the interface
	// in turn and calls f with the registry key; the first error from f
	// aborts iteration.
	ForEach(v any, f func(typ string) error) error
}

type disco struct {
	reg map[string]serviceInfo
}

// New returns an empty registry.
func New() Discovery {
	return &disco{
		reg: make(map[string]serviceInfo),
	}
}

// Register adds service under server keyed by its concrete type.
func (d *disco) Register(server string, service any) error {
	typ := reflect.TypeOf(service)

	logger.KV(xlog.INFO, "server", server, "type", typ)
	key := fmt.Sprintf("%s/%s", server, typ.String())

	if _, ok := d.reg[key]; ok {
		return errors.Errorf("already registered: %s", key)
	}

	d.reg[key] = serviceInfo{
		ServerName: server,
		Service:    service,
		Type:       typ,
	}

	return nil
}

// Find assigns the first registered service implementing *v's interface.
func (d *disco) Find(server string, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.Errorf("a pointer to interface is required, invalid type: %v", rv)
	}

	logger.KV(xlog.DEBUG, "type", rv.String())

	rv = rv.Elem()
	if !rv.IsValid() || rv.Kind() != reflect.Interface {
		return errors.Errorf("non interface type: %s", reflect.TypeOf(v))
	}

	for _, reg := range d.reg {
		if reg.Type.Implements(rv.Type()) &&
			(server == "" || server == reg.ServerName) {
			rv.Set(reflect.ValueOf(reg.Service))
			return nil
		}
	}

	return errors.Errorf("not implemented: %s", rv.String())
}

// ForEach calls f for every registered service implementing *v's interface.
func (d *disco) ForEach(v any, f func(typ string) error) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.Errorf("a pointer to interface is required, invalid type: %v", rv)
	}

	rv = rv.Elem()
	if !rv.IsValid() || rv.Kind() != reflect.Interface {
		return errors.Errorf("non interface type: %s", reflect.TypeOf(v))
	}

	for key, reg := range d.reg {
		if reg.Type.Implements(rv.Type()) {
			rv.Set(reflect.ValueOf(reg.Service))
			err := f(key)
			if err != nil {
				return errors.WithMessagef(err, "failed to execute callback for %s", reg.Type.String())
			}
		}
	}
	return nil
}
