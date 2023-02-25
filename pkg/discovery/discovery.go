package discovery

import (
	"fmt"
	"reflect"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "discovery")

type serviceInfo struct {
	ServerName string
	Service    interface{}
	Type       reflect.Type
}

// Discovery provides service discovery interface
type Discovery interface {
	Register(server string, service interface{}) error
	Find(server string, v interface{}) error
	ForEach(v interface{}, f func(typ string) error) error
}

type disco struct {
	reg map[string]serviceInfo
}

// New return new Discovery
func New() Discovery {
	return &disco{
		reg: make(map[string]serviceInfo),
	}
}

// Register interface
func (d *disco) Register(server string, service interface{}) error {
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

// Find interface
func (d *disco) Find(server string, v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return errors.Errorf("a pointer to interface is required, invalid type: %v", rv)
	}

	logger.KV(xlog.DEBUG, "type", rv.String())

	rv = rv.Elem()
	if !rv.IsValid() || rv.Kind() != reflect.Interface {
		return errors.Errorf("non interface type: %s", reflect.TypeOf(v))
	}

	for _, reg := range d.reg {
		if reg.Type.Implements(rv.Type()) && reg.ServerName == server {
			rv.Set(reflect.ValueOf(reg.Service))
			return nil
		}
	}

	return errors.Errorf("not implemented: " + rv.String())
}

// ForEach interface
func (d *disco) ForEach(v interface{}, f func(typ string) error) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
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
