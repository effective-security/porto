package tlsconfig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"strings"
	"time"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

// NOTE: these functions were cloned from official Go lib
// /usr/local/go/src/crypto/tls/tls.go
// The reason for fork, is that X509KeyPair already parse
// the certificate, but does not update LeafCert.
// In the clone below, we reuse the parsed certs for OCSP
// response validation

// LoadX509KeyPairWithOCSP reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain.
func LoadX509KeyPairWithOCSP(certFile, keyFile string) (*tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ext := path.Ext(certFile)
	ocspfile := certFile[0:len(certFile)-len(ext)] + ".ocsp"

	ocspBytes, err := os.ReadFile(ocspfile)
	if err == nil {
		logger.KV(xlog.TRACE,
			"ocspfile", ocspfile,
		)
	}

	return X509KeyPairWithOCSP(certPEMBlock, keyPEMBlock, ocspBytes)
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (*tls.Certificate, error) {
	return X509KeyPairWithOCSP(certPEMBlock, keyPEMBlock, nil)
}

// X509KeyPairWithOCSP parses a public/private key pair from a pair of
// PEM encoded data.
func X509KeyPairWithOCSP(certPEMBlock, keyPEMBlock, ocspStaple []byte) (*tls.Certificate, error) {
	var cert tls.Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.New("tls: failed to find any PEM data in certificate input")
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched")
		}
		return nil, errors.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes)
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return nil, errors.New("tls: failed to find any PEM data in key input")
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return nil, errors.New("tls: found a certificate rather than a key in the PEM for the private key")
			}
			return nil, errors.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes)
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Allow to load expired for testing
	// now := time.Now()
	// if x509Cert.NotAfter.Before(now) {
	// 	return nil, errors.New("tls: certificate has expired")
	// }

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("tls: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return nil, errors.New("tls: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("tls: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return nil, errors.New("tls: private key does not match public key")
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("tls: private key type does not match public key type")
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return nil, errors.New("tls: private key does not match public key")
		}
	default:
		return nil, errors.New("tls: unknown public key algorithm")
	}

	if len(ocspStaple) > 0 && len(cert.Certificate) > 1 {
		issuer, err := x509.ParseCertificate(cert.Certificate[1])
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse issuer")
		}
		res, err := ocsp.ParseResponseForCert(ocspStaple, x509Cert, issuer)
		if err == nil {
			if res.Status == ocsp.Revoked {
				return nil, errors.New("tls: certificate is revoked")
			}

			if res.NextUpdate.After(time.Now()) {
				// the OCSP is Good and not expired
				cert.OCSPStaple = ocspStaple
			} else {
				logger.KV(xlog.WARNING,
					"status", "ignore_ocsp_staple",
					"reason", "expired",
					"next_update", res.NextUpdate,
				)
			}
		} else {
			logger.KV(xlog.WARNING,
				"status", "ignore_ocsp_staple",
				"reason", "ParseResponseForCert",
				"err", err.Error(),
			)
		}
	}

	cert.Leaf = x509Cert

	return &cert, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
