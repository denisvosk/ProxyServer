// proxy-cert creates one self-signed server certificate in a new protected
// directory. It never modifies Windows' or any browser's trust store.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func validateHost(host string) (string, net.IP, error) {
	if host == "" || strings.TrimSpace(host) != host {
		return "", nil, errors.New("host must be one IP address or ASCII DNS hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return "", nil, errors.New("use the server's public IP address or DNS name, not an unspecified or multicast address")
		}
		return ip.String(), ip, nil
	}
	host = strings.ToLower(host)
	if len(host) > 253 || strings.ContainsAny(host, "/\\:*?@#%[]\x00") {
		return "", nil, errors.New("host must be one IP address or ASCII DNS hostname, without wildcard, port or URL")
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", nil, errors.New("invalid DNS hostname label")
		}
		for _, c := range []byte(label) {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", nil, errors.New("DNS hostname must contain ASCII letters, digits and hyphens only")
			}
			if c < '0' || c > '9' {
				allNumeric = false
			}
		}
	}
	if allNumeric {
		return "", nil, errors.New("invalid IP address")
	}
	return host, nil, nil
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func createCertificate(host, output string, now time.Time) (fingerprint string, err error) {
	host, ip, err := validateHost(host)
	if err != nil {
		return "", err
	}
	if output == "" {
		return "", errors.New("an output directory is required")
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return "", fmt.Errorf("output path: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("generate serial number: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("create certificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	defer clear(keyPEM)
	defer clear(pkcs8)
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return "", fmt.Errorf("create parent directory: %w", err)
	}
	// The leaf directory must be new. Its ACL/mode is restricted before any
	// private-key bytes are written, and existing directories are never reused.
	if err = makeSecureDirectory(output); err != nil {
		return "", fmt.Errorf("create protected output directory: %w", err)
	}
	keyPath, certPath := filepath.Join(output, "key.pem"), filepath.Join(output, "cert.pem")
	keyCreated, certCreated, complete := false, false, false
	defer func() {
		if !complete {
			if keyCreated {
				_ = os.Remove(keyPath)
			}
			if certCreated {
				_ = os.Remove(certPath)
			}
			_ = os.Remove(output) // Remove only an empty directory, never recursively.
		}
	}()
	if err = writeExclusive(keyPath, keyPEM); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	keyCreated = true
	if err = writeExclusive(certPath, certPEM); err != nil {
		return "", fmt.Errorf("write certificate: %w", err)
	}
	certCreated, complete = true, true
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func main() {
	host := flag.String("host", "", "Server public IP address or ASCII DNS hostname")
	output := flag.String("out", "", "New directory for cert.pem and key.pem; must not already exist")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "proxy-cert: unexpected positional arguments")
		os.Exit(2)
	}
	fingerprint, err := createCertificate(*host, *output, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy-cert:", err)
		os.Exit(1)
	}
	fmt.Println("SHA256=" + fingerprint)
}
