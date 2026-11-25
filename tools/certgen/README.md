# Proxy certificate helper

This small Go standard-library helper creates a self-signed ECDSA P-256 server
certificate for one IP address or ASCII DNS name, with a SAN and one-year
validity. It is a server certificate, not a certificate authority. It makes no
changes to Windows, browser, or application trust stores.

```bat
components\proxy-cert.exe --host proxy.example.com --out C:\path\to\new-certificate-directory
```

The output directory must not exist. The helper creates `cert.pem` and `key.pem`
exclusively and never overwrites existing keys. On Windows, the directory is
created with an explicit protected DACL granting inherited access only to the
current account and LocalSystem **before** any key bytes are written. On Unix,
the directory is mode 0700 and both files are mode 0600. The helper prints only
the SHA-256 fingerprint of the DER certificate; it never prints private keys.

Clients must trust the certificate explicitly or use a certificate signed by a
trusted CA. Copy only `cert.pem` to a client that needs to trust this certificate;
keep `key.pem` private on the server. Match the configured host to the actual
server name or IP clients connect to. No wildcard, URL, port, path, multicast,
or unspecified address is accepted.

Build from this directory using Go 1.26.3 or later (release built with 1.26.11):

```bat
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
set GOAMD64=v1
go build -trimpath -buildvcs=false -ldflags="-s -w" -o ..\..\components\proxy-cert.exe .
```

Tests: `go test ./...`. Tests cover certificate/key agreement, SAN verification,
wrong-name and unknown-root rejection, lifetime/constraints, no overwrites,
invalid inputs, and Unix permissions. The Windows ACL implementation is cross-
compiled; this build environment cannot run Windows executables, so its ACL
behavior still needs validation on the target Windows installation.
