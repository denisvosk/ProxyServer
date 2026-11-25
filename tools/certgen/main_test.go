package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCertificateAndNoOverwrite(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "2001:db8::1", "proxy.example"} {
		t.Run(host, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "certificate")
			now := time.Now().UTC().Truncate(time.Second)
			fp, err := createCertificate(host, out, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(fp) != 64 || strings.Contains(fp, "PRIVATE") {
				t.Fatalf("invalid fingerprint %q", fp)
			}
			certData, err := os.ReadFile(filepath.Join(out, "cert.pem"))
			if err != nil {
				t.Fatal(err)
			}
			keyData, err := os.ReadFile(filepath.Join(out, "key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			pair, err := tls.X509KeyPair(certData, keyData)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.VerifyHostname(host); err != nil {
				t.Fatal(err)
			}
			if cert.VerifyHostname("wrong.invalid") == nil {
				t.Fatal("wrong hostname accepted")
			}
			if cert.IsCA || !cert.BasicConstraintsValid || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Fatal("wrong certificate constraints")
			}
			if !cert.NotAfter.Equal(now.AddDate(1, 0, 0)) || !cert.NotBefore.Equal(now.Add(-5*time.Minute)) {
				t.Fatal("wrong certificate lifetime")
			}
			keyBlock, _ := pem.Decode(keyData)
			key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if key.(*ecdsa.PrivateKey).Curve != elliptic.P256() {
				t.Fatal("wrong curve")
			}
			roots := x509.NewCertPool()
			roots.AddCert(cert)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := cert.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: host, CurrentTime: now}); err == nil {
				t.Fatal("untrusted self-signed certificate accepted")
			}
			if _, err := createCertificate(host, out, now); err == nil {
				t.Fatal("overwrote existing output directory")
			}
			after, err := os.ReadFile(filepath.Join(out, "key.pem"))
			if err != nil || !bytes.Equal(keyData, after) {
				t.Fatal("existing private key changed")
			}
			if runtime.GOOS != "windows" {
				for _, p := range []string{out, filepath.Join(out, "key.pem"), filepath.Join(out, "cert.pem")} {
					info, err := os.Stat(p)
					if err != nil || info.Mode().Perm()&0077 != 0 {
						t.Fatal("file or directory permits other accounts")
					}
				}
			}
		})
	}
}

func TestRejectInvalidHostsWithoutCreatingFiles(t *testing.T) {
	for _, host := range []string{"", " ", "*.example.com", "https://example.com", "example.com:443", "a/b", "a\\b", "bad..name", "-name.test", "name-.test", "имя.рф", "256.1.1.1", "0.0.0.0", "::", "224.0.0.1", "[::1]", "example.com ", strings.Repeat("a", 64) + ".test"} {
		out := filepath.Join(t.TempDir(), "must-not-exist")
		if _, err := createCertificate(host, out, time.Now()); err == nil {
			t.Errorf("accepted invalid host %q", host)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("invalid host %q created output", host)
		}
	}
}
