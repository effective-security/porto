// Package limits defines shared server network limits. Zero read deadlines
// and body sizes select conservative defaults; negative values explicitly
// disable individual limits. The handler deadline (Timeouts.Handler) has no
// default: it bounds each request's context only when set. Configure limits
// before starting a server:
//
//	timeouts := limits.Timeouts{Handler: 2 * time.Minute}
//	srv := &http.Server{Handler: timeouts.ApplyHandler(handler)}
//	timeouts.ApplyHTTP(srv)
package limits
