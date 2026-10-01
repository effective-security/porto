package gserver_test

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/tests/mockappcontainer"
)

func ExampleServer() {
	sigs := make(chan os.Signal, 2)

	// A short temporary directory for the Unix socket (socket paths are
	// limited to about 104 bytes), and any free port, so the example cannot
	// collide with other tests; a deployment uses fixed addresses.
	dir, err := os.MkdirTemp("", "gs")
	if err != nil {
		panic("unable to create a socket directory: " + err.Error())
	}
	defer os.RemoveAll(dir)

	cfg := &gserver.Config{
		ListenURLs: []string{"https://127.0.0.1:0", "unix://" + filepath.Join(dir, "gs.sock")},
		Services:   []string{"test"},
		KeepAlive: gserver.KeepAliveCfg{
			MinTime:  time.Second,
			Interval: time.Second,
			Timeout:  time.Second,
		},
		ServerTLS: &gserver.TLSInfo{
			CertFile:      "testdata/test-server.pem",
			KeyFile:       "testdata/test-server-key.pem",
			TrustedCAFile: "testdata/test-server-rootca.pem",
			ClientCAFile:  "testdata/test-server-rootca.pem", // CA bundle for client certificates
		},
		RateLimit: &gserver.RateLimit{
			RequestsPerSecond: 10,
		},
	}

	c := mockappcontainer.NewBuilder().
		WithJwtParser(nil).
		WithDiscovery(discovery.New()).
		Container()

	fact := map[string]gserver.ServiceFactory{
		"test": testServiceFactory,
	}
	fmt.Println("starting server")
	srv, err := gserver.Start("Empty", cfg, c, fact)
	if err != nil {
		panic("unable to start the server: " + err.Error())
	}

	go func() {
		// Send STOP signal after few seconds,
		// in production the service should listen to
		// os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGUSR2, syscall.SIGABRT events
		time.Sleep(3 * time.Second)
		fmt.Println("sending syscall.SIGTERM signal")
		sigs <- syscall.SIGTERM
	}()

	// register for signals, and wait to be shutdown
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	// Block until a signal is received.
	sig := <-sigs

	fmt.Printf("received signal: %v\n", sig)

	srv.Close()
	fmt.Println("stopped server")

	// Output:
	// starting server
	// sending syscall.SIGTERM signal
	// received signal: terminated
	// stopped server
}
