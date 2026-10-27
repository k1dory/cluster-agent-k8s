// Package ca is the agent-identity certificate authority used by the Registrar.
// It is deliberately small: one root, ECDSA P-256, signs CSRs with URI SANs.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// CA holds the signing key and certificate.
type CA struct {
	Cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
}

// LoadOrCreate reads ca.crt/ca.key from dir, generating a self-signed root if absent.
func LoadOrCreate(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if _, err := os.Stat(keyPath); err == nil {
		return Load(certPath, keyPath)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c, err := Generate("agent-sandbox agent CA", 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(c.key.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, c.pem, 0o644); err != nil {
		return nil, err
	}
	return c, nil
}

// Load reads an existing CA.
func Load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return Parse(certPEM, keyPEM)
}

// Parse builds a CA from PEM material.
func Parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("ca: no certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca: no key PEM")
	}
	var key crypto.Signer
	switch kb.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	case "PRIVATE KEY":
		var k any
		k, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err == nil {
			var ok bool
			if key, ok = k.(crypto.Signer); !ok {
				err = errors.New("ca: key is not a signer")
			}
		}
	default:
		err = fmt.Errorf("ca: unsupported key type %q", kb.Type)
	}
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}, nil
}

// Generate creates a new self-signed root in memory.
func Generate(cn string, ttl time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(ttl),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// PEM returns the root certificate.
func (c *CA) PEM() []byte { return c.pem }

// SignRequest is what the Registrar asks the CA to put into a leaf certificate.
type SignRequest struct {
	CSR      *x509.CertificateRequest
	CN       string
	URIs     []*url.URL
	TTL      time.Duration
	NotAfter time.Time // optional hard cap
}

// Sign issues a client certificate. The CSR's own names are ignored: identity comes
// from the Registrar, the CSR only proves possession of the key.
func (c *CA) Sign(req SignRequest) (*x509.Certificate, []byte, error) {
	if err := req.CSR.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("csr signature: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	notAfter := now.Add(req.TTL)
	if !req.NotAfter.IsZero() && req.NotAfter.Before(notAfter) {
		notAfter = req.NotAfter
	}
	if notAfter.After(c.Cert.NotAfter) {
		notAfter = c.Cert.NotAfter
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.CN},
		URIs:         req.URIs,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, req.CSR.PublicKey, c.key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CRL builds a revocation list from serials (hex). Caddy does not consume CRLs natively;
// revocation is enforced by the authz endpoint, the CRL is published for completeness.
func (c *CA) CRL(serialsHex []string) ([]byte, error) {
	var revoked []x509.RevocationListEntry
	for _, s := range serialsHex {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			return nil, fmt.Errorf("bad serial %q", s)
		}
		revoked = append(revoked, x509.RevocationListEntry{SerialNumber: n, RevocationTime: time.Now()})
	}
	tpl := &x509.RevocationList{
		Number:                    big.NewInt(time.Now().Unix()),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: revoked,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, c.Cert, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// NewCSR generates a key and CSR for the agent side (used by agent-init).
func NewCSR(cn string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// ParseCSR decodes a PEM CSR.
func ParseCSR(p []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(p)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("no CERTIFICATE REQUEST block")
	}
	return x509.ParseCertificateRequest(b.Bytes)
}

// Bundle serialises the CA as certificate PEM followed by key PEM, for a shared store.
func (c *CA) Bundle() ([]byte, error) {
	keyDER, err := x509.MarshalECPrivateKey(c.key.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, c.pem...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...), nil
}

// ParseBundle reads what Bundle wrote.
func ParseBundle(b []byte) (*CA, error) {
	var certPEM, keyPEM []byte
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			certPEM = pem.EncodeToMemory(blk)
		case "EC PRIVATE KEY", "PRIVATE KEY":
			keyPEM = pem.EncodeToMemory(blk)
		}
	}
	if certPEM == nil || keyPEM == nil {
		return nil, errors.New("ca bundle: certificate or key missing")
	}
	return Parse(certPEM, keyPEM)
}

// Blobs is where a shared CA lives (the store's GetOrCreateBlob).
type Blobs interface {
	GetOrCreateBlob(ctx context.Context, name string, create func() ([]byte, error)) ([]byte, error)
}

// BlobName is the store key of the shared agent CA.
const BlobName = "agent-ca"

// LoadOrCreateShared returns the agent CA every replica shares: generated once by whoever gets
// to the store first, read by everyone else.
func LoadOrCreateShared(ctx context.Context, st Blobs) (*CA, error) {
	return LoadOrCreateSharedNamed(ctx, st, BlobName, "agent-sandbox agent CA")
}

// LoadOrCreateSharedNamed is LoadOrCreateShared for any CA kept under blob name with cn.
func LoadOrCreateSharedNamed(ctx context.Context, st Blobs, name, cn string) (*CA, error) {
	data, err := st.GetOrCreateBlob(ctx, name, func() ([]byte, error) {
		c, err := Generate(cn, 10*365*24*time.Hour)
		if err != nil {
			return nil, err
		}
		return c.Bundle()
	})
	if err != nil {
		return nil, err
	}
	return ParseBundle(data)
}

// WriteTo stores the CA as <dir>/<base>.crt and <dir>/<base>.key for a program that reads
// PEM files (Caddy's pki root) and returns both paths. The key is 0640: Caddy runs next to
// sandboxd in the same pod under another user with every capability dropped (no
// CAP_DAC_OVERRIDE, so root obeys the mode bits), and reads it through the pod's group
// (the chart's fsGroup); nobody outside the pod sees the directory. The directories WriteTo
// creates on the way, nested ones included, let the group through (0750) for the same
// reader; directories that already exist (a volume's mount point) are left as they are.
func (c *CA) WriteTo(dir, base string) (certPath, keyPath string, err error) {
	if err := mkdirAllGroup(dir); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(c.key.(*ecdsa.PrivateKey))
	if err != nil {
		return "", "", err
	}
	certPath, keyPath = filepath.Join(dir, base+".crt"), filepath.Join(dir, base+".key")
	if err := os.WriteFile(certPath, c.pem, 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o640); err != nil {
		return "", "", err
	}
	// The modes as stated, whatever the process's umask (0077 would leave the group out).
	if err := os.Chmod(certPath, 0o644); err != nil {
		return "", "", err
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// mkdirAllGroup creates dir and the missing directories above it, each 0750 whatever the
// process's umask: the mode is set explicitly on every directory created here, never on one
// found in place.
func mkdirAllGroup(dir string) error {
	dir = filepath.Clean(dir)
	var missing []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, d)
		if parent := filepath.Dir(d); parent == d {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o750); err != nil && !os.IsExist(err) {
			return err
		}
		if err := os.Chmod(missing[i], 0o750); err != nil {
			return err
		}
	}
	return nil
}
