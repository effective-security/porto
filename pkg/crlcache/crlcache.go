package crlcache

import (
	"crypto/x509"
)

// Verifier provides an interface to check revocation status
type Verifier interface {
	// Update the cache
	Update() error

	// Verify returns OCSP status:
	//   ocsp.Revoked - the certificate found in CRL
	//   ocsp.Good - the certificate not found in a valid CRL
	//   ocsp.Unknown - no CRL or OCSP response found for the certificate
	Verify(crt *x509.Certificate, issuer *x509.Certificate) (int, error)
}

// TODO: implement
