package gserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccreds "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// portoRepo and gserverLogPkg register the package logger of gserver.
	portoRepo     = "github.com/effective-security/porto"
	gserverLogPkg = "gserver"

	callLogService = "porto.test.CallLog"
	callLogUnary   = "/porto.test.CallLog/Unary"
	callLogStream  = "/porto.test.CallLog/Stream"
	callLogAgent   = "calllog-test"
	// callLogProxies trusts the test client's loopback socket peer, so the
	// x-forwarded-for metadata it sends names the client.
	callLogProxies = "127.0.0.0/8"
	callLogClient  = "203.0.113.9"
	callLogRole    = "admin"
	callTimeout    = 5 * time.Second
	// logCtx stands for the correlation ID in logBuffer.lines.
	logCtx = "<ctx>"
	// tooManyRequests is the httperror code of a rate-limited call.
	tooManyRequests = "too_many_requests"
	// skipAgent is a LoggerSkipPath agent that is a substring of
	// telemetry.NoAgent.
	skipAgent = "agent"
	// webAllowedOrigin is the only origin the CORS policy of
	// TestGRPCHandlerLogFields allows; webOtherOrigin is rejected.
	webAllowedOrigin = "https://app.example"
	webOtherOrigin   = "https://other.example"
	// loopbackPeer stands for the test client's socket address in
	// TestGRPCHandlerLogFields.
	loopbackPeer = "<loopback>"
)

// callLogDesc is a service whose unary and server-streaming methods answer
// with their request.
var callLogDesc = grpc.ServiceDesc{
	ServiceName: callLogService,
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Unary",
			Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				in := &wrapperspb.StringValue{}
				if err := dec(in); err != nil {
					return nil, err
				}
				info := &grpc.UnaryServerInfo{Server: srv, FullMethod: callLogUnary}
				return interceptor(ctx, in, info, func(_ context.Context, req any) (any, error) {
					return req, nil
				})
			},
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Stream",
			ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				in := &wrapperspb.StringValue{}
				if err := stream.RecvMsg(in); err != nil {
					return err
				}
				return stream.SendMsg(in)
			},
		},
	},
}

// logBuffer collects the lines the server goroutines log while the test
// reads them.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// volatileLogKeys vary between runs: logBuffer.lines drops them.
var volatileLogKeys = []string{"time", "duration"}

// lines returns the JSON log lines whose key has value, in order, without
// volatileLogKeys and with the correlation ID, in ctx and in other string
// values, replaced by logCtx.
func (b *logBuffer) lines(t *testing.T, key, value string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var lines []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(b.buf.String()))
	for scanner.Scan() {
		line := map[string]any{}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &line), scanner.Text())
		if line[key] != value {
			continue
		}
		for _, k := range volatileLogKeys {
			delete(line, k)
		}
		if id, ok := line["ctx"].(string); ok {
			require.NotEmpty(t, id)
			for k, v := range line {
				if str, ok := v.(string); ok {
					line[k] = strings.ReplaceAll(str, id, logCtx)
				}
			}
		}
		lines = append(lines, line)
	}
	require.NoError(t, scanner.Err())
	return lines
}

// captureLogs installs a process-global JSON log formatter, with the
// gserver logger at DEBUG, the most verbose xlog level, which includes the
// TRACE lines of successful calls and the Config.DebugLogs lines, for the
// rest of the test.
func captureLogs(t *testing.T) *logBuffer {
	t.Helper()
	logs := &logBuffer{}
	t.Cleanup(xlog.InstallFormatter(xlog.NewJSONFormatter(logs)))
	xlog.SetPackageLogLevel(portoRepo, gserverLogPkg, xlog.DEBUG)
	// INFO is the default level
	t.Cleanup(func() { xlog.SetPackageLogLevel(portoRepo, gserverLogPkg, xlog.INFO) })
	return logs
}

// dialCallLog returns a client of the callLogDesc service at addr whose
// User-Agent starts with callLogAgent.
func dialCallLog(t *testing.T, addr string, creds grpccreds.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds), grpc.WithUserAgent(callLogAgent))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// callLogContext returns a call context whose metadata forwards
// callLogClient and asks headerIdentity for role.
func callLogContext(role string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	return metadata.AppendToOutgoingContext(ctx,
		header.XForwardedFor, callLogClient,
		testRoleHeader, role,
	), cancel
}

// callUnary calls callLogUnary as role.
func callUnary(conn *grpc.ClientConn, role string) error {
	ctx, cancel := callLogContext(role)
	defer cancel()
	return conn.Invoke(ctx, callLogUnary, wrapperspb.String("hi"), &wrapperspb.StringValue{})
}

// callStream calls callLogStream as role and reads it to the end.
func callStream(conn *grpc.ClientConn, role string) error {
	ctx, cancel := callLogContext(role)
	defer cancel()
	cs, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, callLogStream)
	if err != nil {
		return err
	}
	if err = cs.SendMsg(wrapperspb.String("hi")); err != nil {
		return err
	}
	if err = cs.CloseSend(); err != nil {
		return err
	}
	for {
		if err = cs.RecvMsg(&wrapperspb.StringValue{}); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// callLine returns the logRequest line of a call to res that ended with
// code, as logBuffer.lines returns it; extra holds the context entries of
// the line: ctx for unary calls, and the role and user that identity adds.
func callLine(res, remote, agent string, code codes.Code, extra map[string]any) map[string]any {
	line := map[string]any{
		"level":  "T",
		"pkg":    gserverLogPkg,
		"func":   "logRequest",
		"req":    map[string]any{}, // a reflect.Type marshals as {}
		"res":    res,
		"remote": remote,
		"agent":  agent,
		"code":   float64(code),
	}
	maps.Copy(line, extra)
	return line
}

// TestLogRequestCaller checks that the log line and the GRPCReqByRole
// metric of unary and streaming calls report the caller that the identity
// interceptor resolved (formerly P-105): the client IP forwarded by a
// trusted proxy as remote, the User-Agent as agent, and the identity's role.
// A call that identity rejects is logged with the same client IP and
// counted as guest, and the identity WARNING line has the client IP as
// remote. It installs process-global log and metrics sinks, so it is not
// parallel.
func TestLogRequestCaller(t *testing.T) {
	logs := captureLogs(t)
	counts := newMetricsSink(t)

	trust, err := identity.ParseTrustedProxies([]string{callLogProxies})
	require.NoError(t, err)
	s := &Server{
		name:           "calllog",
		identity:       headerIdentity{},
		trustedProxies: trust,
	}
	gs := grpcServer(s, nil, nil)
	gs.RegisterService(&callLogDesc, struct{}{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn := dialCallLog(t, lis.Addr().String(), insecure.NewCredentials())
	agent := callLogAgent + " grpc-go/" + grpc.Version

	before := counts()
	require.NoError(t, callUnary(conn, callLogRole))
	assert.Equal(t, codes.Unauthenticated, status.Code(callUnary(conn, deniedRole)))
	require.NoError(t, callStream(conn, callLogRole))
	assert.Equal(t, codes.Unauthenticated, status.Code(callStream(conn, deniedRole)))

	// The ctx, role and user of a unary line come from the context entries
	// of correlation and identity; stream lines have none, because the
	// stream log interceptor runs outside correlation, which creates them.
	admin := map[string]any{
		"ctx":  logCtx,
		"role": callLogRole,
		"user": "user",
	}
	withCtx := map[string]any{"ctx": logCtx}
	assert.Equal(t, []map[string]any{
		callLine(callLogUnary, callLogClient, agent, codes.OK, admin),
		callLine(callLogUnary, callLogClient, agent, codes.Unauthenticated, withCtx),
		callLine(callLogStream, callLogClient, agent, codes.OK, nil),
		callLine(callLogStream, callLogClient, agent, codes.Unauthenticated, nil),
	}, logs.lines(t, "func", "logRequest"))

	denied := func(method string, extra map[string]any) map[string]any {
		line := map[string]any{
			"level":  "W",
			"pkg":    "context",
			"func":   "createIdentityContext",
			"reason": "access_denied",
			"method": method,
			"remote": callLogClient,
			"err":    "invalid credentials",
		}
		maps.Copy(line, extra)
		return line
	}
	// identity runs inside correlation in both chains
	assert.Equal(t, []map[string]any{
		denied(callLogUnary, withCtx),
		denied(callLogStream, withCtx),
	}, logs.lines(t, "reason", "access_denied"))

	want := map[string]int{}
	for _, m := range []struct {
		api  string
		code codes.Code
		role string
	}{
		{callLogUnary, codes.OK, callLogRole},
		{callLogUnary, codes.Unauthenticated, roles.GuestRoleName},
		{callLogStream, codes.OK, callLogRole},
		{callLogStream, codes.Unauthenticated, roles.GuestRoleName},
	} {
		labels := ";api=" + m.api + ";status=" + m.code.String()
		want[metricsTestPrefix+"_rpc_requests_perf"+labels]++
		want[metricsTestPrefix+"_rpc_requests_role"+labels+";role="+m.role]++
	}
	assert.Equal(t, want, delta(before, counts()))
}

// TestLogRequestSkipNoAgent checks that a call without a User-Agent logs
// telemetry.NoAgent as its agent, while SkipLogPaths keeps matching the
// User-Agent as sent: an agent entry that is a substring of NoAgent skips
// neither the line nor the metrics of such a call. It installs
// process-global log and metrics sinks, so it is not parallel.
func TestLogRequestSkipNoAgent(t *testing.T) {
	logs := captureLogs(t)
	counts := newMetricsSink(t)
	s := &Server{
		cfg: Config{
			SkipLogPaths: []telemetry.LoggerSkipPath{
				{Path: "*", Agent: skipAgent},
			},
		},
	}
	info := &grpc.UnaryServerInfo{FullMethod: callLogUnary}
	ok := func(context.Context, any) (any, error) { return nil, nil }

	before := counts()
	_, err := s.newLogUnaryInterceptor()(context.Background(), nil, info, ok)
	require.NoError(t, err)
	// skipped: the agent entry is a substring of the User-Agent as sent
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(header.UserAgent, callLogAgent+"-"+skipAgent))
	_, err = s.newLogUnaryInterceptor()(ctx, nil, info, ok)
	require.NoError(t, err)

	// a call without a peer has no client IP
	line := callLine(callLogUnary, "", telemetry.NoAgent, codes.OK, nil)
	line["req"] = nil
	assert.Equal(t, []map[string]any{line}, logs.lines(t, "func", "logRequest"))
	labels := ";api=" + callLogUnary + ";status=" + codes.OK.String()
	assert.Equal(t, map[string]int{
		metricsTestPrefix + "_rpc_requests_perf" + labels:                                  1,
		metricsTestPrefix + "_rpc_requests_role" + labels + ";role=" + roles.GuestRoleName: 1,
	}, delta(before, counts()))
}

// callLogServer is the Service that registers callLogDesc.
type callLogServer struct{}

func (callLogServer) Name() string  { return callLogService }
func (callLogServer) IsReady() bool { return true }
func (callLogServer) Close()        {}

func (callLogServer) RegisterGRPC(gs *grpc.Server) {
	gs.RegisterService(&callLogDesc, callLogServer{})
}

// startCallLog starts a server with callLogServer on a plaintext listener,
// or a TLS one when cfg.ServerTLS is set, trusting callLogProxies, and
// returns its address. cfg may set any field except ListenURLs, Services
// and TrustedProxyCIDRs.
func startCallLog(t *testing.T, cfg *Config) string {
	t.Helper()
	cfg.ListenURLs = []string{"http://127.0.0.1:0"}
	if cfg.ServerTLS != nil {
		cfg.ListenURLs = []string{"https://127.0.0.1:0"}
	}
	cfg.Services = []string{callLogService}
	cfg.TrustedProxyCIDRs = []string{callLogProxies}
	factories := map[string]ServiceFactory{
		callLogService: func(server GServer) any {
			return func() { server.AddService(callLogServer{}) }
		},
	}
	srv, err := Start("calllog", cfg, discoveryContainer(t), factories)
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	return srv.(*Server).Listeners[0].Addr().String()
}

// callLogClientTLS returns the client TLS configuration for lifecycleTLS.
func callLogClientTLS(t *testing.T) *tls.Config {
	t.Helper()
	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", lifecycleTLS.TrustedCAFile)
	require.NoError(t, err)
	// the legacy test fixture has no SANs
	clientTLS.InsecureSkipVerify = true
	return clientTLS
}

// TestLogRequestRemoteListeners checks that a server built by Start logs
// the client IP a trusted proxy forwards as the remote of unary and
// streaming calls on plaintext listeners and on TLS listeners, where gRPC
// is served through grpcHandlerFunc and the trusted proxy HTTP handler,
// including a call the rate limiter rejects before identity runs, whose
// error line has the remote too. It installs a process-global log
// formatter and starts a TLS reloader, so it is not parallel.
func TestLogRequestRemoteListeners(t *testing.T) {
	for _, tc := range []struct {
		name string
		tls  *TLSInfo
	}{
		{name: "plaintext"},
		{name: "tls", tls: lifecycleTLS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			enabled := true
			addr := startCallLog(t, &Config{
				ServerTLS: tc.tls,
				RateLimit: &RateLimit{
					Enabled:           &enabled,
					RequestsPerSecond: 1,
				},
			})
			creds := insecure.NewCredentials()
			if tc.tls != nil {
				creds = grpccreds.NewTLS(callLogClientTLS(t))
			}
			conn := dialCallLog(t, addr, creds)
			agent := callLogAgent + " grpc-go/" + grpc.Version

			require.NoError(t, callUnary(conn, ""))
			// one token per client IP and path
			limited := callUnary(conn, "")
			assert.Equal(t, codes.ResourceExhausted, status.Code(limited))
			require.NoError(t, callStream(conn, ""))
			unary := map[string]any{"ctx": logCtx}
			assert.Equal(t, []map[string]any{
				callLine(callLogUnary, callLogClient, agent, codes.OK, unary),
				callLine(callLogUnary, callLogClient, agent, codes.ResourceExhausted, unary),
				callLine(callLogStream, callLogClient, agent, codes.OK, nil),
			}, logs.lines(t, "func", "logRequest"))
			assert.Equal(t, []map[string]any{
				{
					"level":  "W",
					"pkg":    gserverLogPkg,
					"ctx":    logCtx,
					"func":   "logError",
					"type":   "API_ERROR",
					"method": callLogUnary,
					"remote": callLogClient,
					"code":   codes.ResourceExhausted.String(),
					"err":    "request " + logCtx + ": " + tooManyRequests + ": " + status.Convert(limited).Message(),
				},
			}, logs.lines(t, "func", "logError"))
		})
	}
}

// TestGRPCHandlerLogFields checks the client address and User-Agent fields
// of the lines grpcHandlerFunc logs on a TLS listener: remote is the client
// IP a trusted proxy forwards, peer the socket address and agent
// telemetry.NoAgent for a request without a User-Agent, in the
// cors_not_allowed line of a gRPC-Web call from a disallowed origin and in
// the Config.DebugLogs lines of a gRPC call and a REST request. It
// installs a process-global log formatter and starts a TLS reloader, so it
// is not parallel.
func TestGRPCHandlerLogFields(t *testing.T) {
	logs := captureLogs(t)
	enabled := true
	addr := startCallLog(t, &Config{
		ServerTLS: lifecycleTLS,
		DebugLogs: true,
		CORS: &CORS{
			Enabled:        &enabled,
			AllowedOrigins: []string{webAllowedOrigin},
		},
	})
	client := &http.Client{
		Timeout: callTimeout,
		Transport: &http.Transport{
			TLSClientConfig: callLogClientTLS(t),
			// the TLS listener answers a client without ALPN with HTTP/2 frames
			ForceAttemptHTTP2: true,
		},
	}
	t.Cleanup(client.CloseIdleConnections)
	do := func(method, path, contentType string) int {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, "https://"+addr+path, http.NoBody)
		require.NoError(t, err)
		req.Header.Set(header.XForwardedFor, callLogClient)
		// an empty value suppresses the client's default User-Agent
		req.Header.Set(header.UserAgent, "")
		if contentType != "" {
			req.Header.Set(header.ContentType, contentType)
			req.Header.Set(header.Origin, webOtherOrigin)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp.StatusCode
	}
	// handlerLines replaces the loopback socket address of each line by
	// loopbackPeer and drops func, the name of a grpcHandlerFunc closure,
	// which changes when an earlier closure is added.
	handlerLines := func(lines []map[string]any) []map[string]any {
		for _, line := range lines {
			peer, ok := line["peer"].(string)
			require.True(t, ok, line)
			host, _, err := net.SplitHostPort(peer)
			require.NoError(t, err)
			assert.Equal(t, "127.0.0.1", host)
			line["peer"] = loopbackPeer
			delete(line, "func")
		}
		return lines
	}

	assert.Equal(t, http.StatusForbidden, do(http.MethodPost, callLogUnary, header.ApplicationGRPCWebProto))
	assert.Equal(t, []map[string]any{
		{
			"level":        "I",
			"pkg":          gserverLogPkg,
			"reason":       "cors_not_allowed",
			"method":       http.MethodPost,
			"ct":           header.ApplicationGRPCWebProto,
			"remote":       callLogClient,
			"peer":         loopbackPeer,
			"agent":        telemetry.NoAgent,
			"content-type": header.ApplicationGRPC,
			"accept":       "",
			"url":          callLogUnary,
		},
	}, handlerLines(logs.lines(t, "reason", "cors_not_allowed")))

	conn := dialCallLog(t, addr, grpccreds.NewTLS(callLogClientTLS(t)))
	require.NoError(t, callUnary(conn, ""))
	assert.Equal(t, http.StatusNotFound, do(http.MethodGet, "/v1/items", ""))
	debug := logs.lines(t, "level", "D")
	assert.Equal(t, []map[string]any{
		{
			"level":           "D",
			"pkg":             gserverLogPkg,
			"method":          http.MethodPost,
			"ct":              header.ApplicationGRPC,
			"remote":          callLogClient,
			"peer":            loopbackPeer,
			"agent":           callLogAgent + " grpc-go/" + grpc.Version,
			"content-type":    header.ApplicationGRPC,
			"accept":          "",
			"content-length":  float64(-1),
			"proto_ver_minor": float64(0),
			"proto_ver_major": float64(2),
			"url":             callLogUnary,
		},
		{
			"level":           "D",
			"pkg":             gserverLogPkg,
			"handle":          "otherHandler",
			"method":          http.MethodGet,
			"ct":              "",
			"remote":          callLogClient,
			"peer":            loopbackPeer,
			"agent":           telemetry.NoAgent,
			"content-type":    "",
			"accept":          "",
			"content-length":  float64(0),
			"proto_ver_minor": float64(0),
			"proto_ver_major": float64(2),
			"url":             "/v1/items",
		},
	}, handlerLines(debug))
}
