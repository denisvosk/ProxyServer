# mtg desktop integration

This source is based on the MIT-licensed `9seconds/mtg` release **v2.3.0**,
commit `5899a2f5b3bda263a885c3da450388a198f67cda`.

Two narrow CLI adaptations are applied for the Windows desktop controller:

1. `run -` reads TOML configuration from standard input, with a 64 KiB cap.
   The controller can pass the secret through an inherited anonymous pipe,
   without putting it in command-line arguments or a plaintext config file.
2. `run --skip-startup-checks -` skips the optional SNI/public-IP diagnostic
   before opening the listener. Ordinary `run` and `simple-run` retain the
   upstream diagnostic behavior. FakeTLS validation, cryptography, anti-replay,
   Telegram routing, and the data transport are not modified.

The complete change is in `DESKTOP_PATCH.diff`. A regression test for valid,
invalid, and oversized stdin input is added to `internal/utils`.

The bundled binary identifies itself as `2.3.0-desktop.1`. It was cross-compiled
for Windows/amd64 with the official Go 1.26.11 toolchain, CGO disabled.

## Rebuild on Windows

Install Go 1.26.11 or a compatible newer release. From this directory:

```bat
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=2.3.0-desktop.1" -o ..\..\components\mtg.exe .
```

Go downloads the dependency versions locked by `go.mod` and `go.sum`. The Go
toolchain is not included in this archive. The app runs the already-built EXE;
Go is needed only when rebuilding the component.

The desktop controller runs:

```text
components\mtg.exe run --skip-startup-checks -
```

Configuration is supplied on stdin and then the pipe is closed. Debug logging,
remote IP lists, telemetry exporters, and automatic DC updates are disabled by
the controller's generated configuration. Stock mtg protocol behavior remains.

## Validation limits

The `internal/config`, `internal/utils`, and `mtglib` Go tests passed on Linux.
The adapted Linux process was checked for stdin startup, opening the requested
loopback TCP port, clean listener teardown, secret-free stdout/stderr for a
valid configuration, and rejecting stdin above 64 KiB. The Windows binary was
cross-compiled; it was not run on real Windows in the build workspace. No live
Telegram account or conversation was used during these checks.

Upstream source: https://github.com/9seconds/mtg/tree/v2.3.0
Upstream license: `LICENSE` in this directory.
