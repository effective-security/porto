package discovery_test

import (
	"testing"

	"github.com/effective-security/porto/pkg/discovery"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscovery(t *testing.T) {
	f := &fooImpl{}
	b := &barImpl{}

	srv := "TestDiscovery"
	d := discovery.New()
	err := d.Register(srv, f)
	require.NoError(t, err)

	err = d.Register(srv, b)
	require.NoError(t, err)
	err = d.Register(srv, &barImpl{})
	require.EqualError(t, err, "already registered: TestDiscovery/*discovery_test.barImpl")

	var f2 foo
	err = d.Find(&f2)
	require.NoError(t, err)
	require.NotNil(t, f2)
	assert.Equal(t, f.GetName(), f2.GetName())

	count := 0
	err = d.ForEach(&f2, func(key string) error {
		count++
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, f2)
	assert.Equal(t, 1, count)

	var nonPointer bar
	err = d.Find(nonPointer)
	require.EqualError(t, err, "a pointer to interface is required, invalid type: <invalid reflect.Value>")

	err = d.Find(err)
	require.EqualError(t, err, "non interface type: *errors.fundamental")

	err = d.Find(&err)
	require.EqualError(t, err, "not implemented: <error Value>")

	err = d.ForEach(nonPointer, func(key string) error {
		return nil
	})
	require.EqualError(t, err, "a pointer to interface is required, invalid type: <invalid reflect.Value>")

	err = d.ForEach(err, func(key string) error {
		return nil
	})
	require.EqualError(t, err, "non interface type: *errors.fundamental")

	err = d.ForEach(&nonPointer, func(key string) error {
		return errors.Errorf("callback failed")
	})
	require.EqualError(t, err, "failed to execute callback for *discovery_test.barImpl: callback failed")
}

type foo interface {
	GetName() string
}

type fooImpl struct{}

func (f *fooImpl) GetName() string { return "foo" }

type bar interface {
	IsSupported() bool
}
type barImpl struct{}

func (f *barImpl) IsSupported() bool { return true }
