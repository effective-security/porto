package restserver_test

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto", "rest_test")

func ExampleServer() {
	sigs := make(chan os.Signal, 2)

	tlsCfg := &tlsConfig{
		CertFile:       "testdata/test-server.pem",
		KeyFile:        "testdata/test-server-key.pem",
		TrustedCAFile:  "testdata/test-server-rootca.pem",
		WithClientAuth: false,
	}

	tlsInfo, tlsloader, err := createServerTLSInfo(tlsCfg)
	if err != nil {
		panic("unable to create TLS config")
	}
	defer tlsloader.Close()

	cfg := &serverConfig{
		BindAddr: ":8181",
	}

	server, err := rest.New("v1.0.123", "", cfg, tlsInfo)
	if err != nil {
		panic("unable to create the server")
	}

	svc := NewService(server)
	server.AddService(svc)

	fmt.Println("starting server")
	err = server.StartHTTP()
	if err != nil {
		logger.Panicf("unable to start the server: [%+v]", err)
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
	signal.Notify(sigs, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGUSR2, syscall.SIGABRT)
	// Block until a signal is received.
	sig := <-sigs

	server.StopHTTP()
	fmt.Println("stopped server")

	// SIGUSR2 is triggered by the upstart pre-stop script, we don't want
	// to actually exit the process in that case until upstart sends SIGTERM
	if sig == syscall.SIGUSR2 {
		select {
		case <-time.After(time.Second * 5):
			logger.KV(xlog.INFO, "status", "service shutdown from SIGUSR2 complete, waiting for SIGTERM to exit")
		case sig = <-sigs:
			logger.KV(xlog.INFO, "status", "exiting", "reason", "received_signal", "sig", sig)
		}
	}

	// Output:
	// starting server
	// sending syscall.SIGTERM signal
	// stopped server
}
