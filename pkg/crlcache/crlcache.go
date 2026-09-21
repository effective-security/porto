package crlcache

import (
	"crypto/x509"
)

// Verifier checks the revocation status of a certificate against its issuer.
// Implementations must be safe for concurrent use: transport.NewTLSListener
// calls Verify from concurrent handshake goroutines.
type Verifier interface {
	// Update refreshes the underlying CRL/OCSP cache.
	Update() error

	// Verify returns OCSP status:
	//   ocsp.Revoked - the certificate found in CRL
	//   ocsp.Good - the certificate not found in a valid CRL
	//   ocsp.Unknown - no CRL or OCSP response found for the certificate
	Verify(crt *x509.Certificate, issuer *x509.Certificate) (int, error)
}
