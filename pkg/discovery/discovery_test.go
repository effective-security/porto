package discovery_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscovery(t *testing.T) {
	t.Parallel()
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
	err = d.Find(srv, &f2)
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
	err = d.Find(srv, nonPointer)
	require.EqualError(t, err, "a pointer to interface is required, invalid type: <invalid reflect.Value>")

	err = d.Find(srv, err)
	require.EqualError(t, err, "non interface type: *withstack.withStack")

	err = d.Find(srv, &err)
	require.EqualError(t, err, "not implemented: <error Value>")

	err = d.ForEach(nonPointer, func(key string) error {
		return nil
	})
	require.EqualError(t, err, "a pointer to interface is required, invalid type: <invalid reflect.Value>")

	err = d.ForEach(err, func(key string) error {
		return nil
	})
	require.EqualError(t, err, "non interface type: *withstack.withStack")

	err = d.ForEach(&nonPointer, func(key string) error {
		return errors.Errorf("callback failed")
	})
	require.EqualError(t, err, "failed to execute callback for *discovery_test.barImpl: callback failed")
}

func TestRegisterRejectsNil(t *testing.T) {
	t.Parallel()

	var typedNil *fooImpl
	for _, service := range []any{nil, typedNil} {
		d := discovery.New()
		err := d.Register("server", service)
		require.EqualError(t, err, "service is nil")

		var found foo
		err = d.Find("server", &found)
		require.EqualError(t, err, "not implemented: <discovery_test.foo Value>")
	}
}

func TestConcurrentRegisterAndLookup(t *testing.T) {
	t.Parallel()

	d := discovery.New()
	require.NoError(t, d.Register("initial", &fooImpl{}))

	const registrations = 100
	start := make(chan struct{})
	results := make(chan error, 3)
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		<-start
		for i := range registrations {
			if err := d.Register(fmt.Sprintf("server-%d", i), &fooImpl{}); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	}()
	go func() {
		defer workers.Done()
		<-start
		for range registrations {
			var found foo
			if err := d.Find("", &found); err != nil {
				results <- err
				return
			}
			if found == nil {
				results <- errors.New("Find returned no service")
				return
			}
		}
		results <- nil
	}()
	go func() {
		defer workers.Done()
		<-start
		for range registrations {
			var found foo
			count := 0
			if err := d.ForEach(&found, func(string) error {
				count++
				return nil
			}); err != nil {
				results <- err
				return
			}
			if count == 0 {
				results <- errors.New("ForEach returned no services")
				return
			}
		}
		results <- nil
	}()

	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
}

func TestForEachCallbackCanRegister(t *testing.T) {
	t.Parallel()

	d := discovery.New()
	require.NoError(t, d.Register("initial", &fooImpl{}))
	var found foo
	count := 0
	err := d.ForEach(&found, func(string) error {
		count++
		return d.Register("from-callback", &fooImpl{})
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	err = d.Find("from-callback", &found)
	require.NoError(t, err)
	assert.NotNil(t, found)
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
