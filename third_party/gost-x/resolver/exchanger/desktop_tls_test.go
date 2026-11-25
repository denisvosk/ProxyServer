package exchanger

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xlogger "github.com/go-gost/x/logger"
	"github.com/miekg/dns"
)

// These regression tests use only loopback servers and httptest's test
// certificate. They do not contact an external DNS or certificate service.
func TestDesktopSecureDNSDefaults(t *testing.T) {
	for _, tt := range []struct{ url, address, name string }{
		{"tls://resolver.example", "resolver.example:853", "resolver.example"},
		{"dot://[::1]", "[::1]:853", "::1"},
		{"tls://127.0.0.1:8853", "127.0.0.1:8853", "127.0.0.1"},
		{"https://resolver.example/dns-query", "https://resolver.example/dns-query", "resolver.example"},
	} {
		ex, err := NewExchanger(tt.url, LoggerOption(xlogger.Nop()))
		if err != nil {
			t.Fatal(err)
		}
		e := ex.(*exchanger)
		if e.addr != tt.address {
			t.Errorf("%s address = %q, want %q", tt.url, e.addr, tt.address)
		}
		cfg := e.options.tlsConfig
		if cfg == nil || cfg.InsecureSkipVerify || cfg.MinVersion != tls.VersionTLS12 || cfg.ServerName != tt.name {
			t.Fatalf("%s did not create a verifying TLS 1.2+ configuration", tt.url)
		}
		if e.client != nil && e.client.Transport.(*http.Transport).TLSClientConfig != cfg {
			t.Fatal("DoH transport does not use its verifying configuration")
		}
	}
	for _, address := range []string{"udp://[::1]", "tcp://[::1]"} {
		ex, err := NewExchanger(address, LoggerOption(xlogger.Nop()))
		if err != nil || ex.(*exchanger).addr != "[::1]:53" {
			t.Fatalf("IPv6 DNS default port: %v, %v", ex, err)
		}
	}
}

func TestDesktopEncryptedDNSCertificateVerification(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("local-test.invalid.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	answer := new(dns.Msg)
	answer.SetReply(query)
	answer.Authoritative = true
	response, err := answer.Pack()
	if err != nil {
		t.Fatal(err)
	}

	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	doh.Config.ErrorLog = log.New(io.Discard, "", 0)
	doh.StartTLS()
	defer doh.Close()

	dot, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: doh.TLS.Certificates,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dot.Close()
	go func() {
		for {
			c, acceptErr := dot.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				conn := &dns.Conn{Conn: c}
				request, readErr := conn.ReadMsg()
				if readErr != nil {
					return
				}
				reply := new(dns.Msg)
				reply.SetReply(request)
				reply.Authoritative = true
				_ = conn.WriteMsg(reply)
			}(c)
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(doh.Certificate())
	for _, endpoint := range []string{"tls://" + dot.Addr().String(), doh.URL + "/dns-query"} {
		for _, tc := range []struct {
			name      string
			cfg       *tls.Config
			wantError bool
		}{
			{"default-untrusted", nil, true},
			{"trusted-correct-name", &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, false},
			{"trusted-wrong-name", &tls.Config{RootCAs: roots, ServerName: "wrong.example", MinVersion: tls.VersionTLS12}, true},
		} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				opts := []Option{LoggerOption(xlogger.Nop()), TimeoutOption(3 * time.Second)}
				if tc.cfg != nil {
					opts = append(opts, TLSConfigOption(tc.cfg))
				}
				ex, err := NewExchanger(endpoint, opts...)
				if err != nil {
					t.Fatal(err)
				}
				if e := ex.(*exchanger); e.client != nil {
					defer e.client.CloseIdleConnections()
				}
				got, err := ex.Exchange(context.Background(), wire)
				if tc.wantError {
					if err == nil {
						t.Fatal("accepted an untrusted or hostname-mismatched certificate")
					}
					return
				}
				if err != nil {
					t.Fatalf("trusted TLS exchange failed: %v", err)
				}
				var result dns.Msg
				if err := result.Unpack(got); err != nil || !result.Response || result.Id != query.Id {
					t.Fatalf("invalid DNS reply: %v", err)
				}
			})
		}
	}
}
