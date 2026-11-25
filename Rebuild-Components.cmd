@echo off
setlocal
cd /d "%~dp0"
where go >nul 2>&1
if errorlevel 1 (
  echo Go is required to rebuild the bundled components. The ready release does not require Go.
  echo Install Go 1.26.11 or a compatible later version, then run this file again.
  exit /b 1
)
go version
set "GOTOOLCHAIN=local"
set "GOWORK=off"
set "CGO_ENABLED=0"
set "GOOS=windows"
set "GOARCH=amd64"
set "GOAMD64=v1"
if not exist "components" mkdir "components"
echo Building GOST 3.3.3-desktop.1 with the documented local runtime patches...
pushd "third_party\gost"
go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=3.3.3-desktop.1" -o ..\..\components\gost.exe ./cmd/gost
if errorlevel 1 goto :build_failed
popd
echo Building mtg 2.3.0-desktop.1 with the documented stdin CLI patch...
pushd "third_party\mtg"
go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=2.3.0-desktop.1" -o ..\..\components\mtg.exe .
if errorlevel 1 goto :build_failed
popd
echo Building the standard-library certificate helper...
pushd "tools\certgen"
go build -trimpath -buildvcs=false -ldflags="-s -w" -o ..\..\components\proxy-cert.exe .
if errorlevel 1 goto :build_failed
popd
echo Components built successfully. Build the native application with Build.cmd or ProxyServer.sln.
exit /b 0

:build_failed
popd
echo A component build failed. See the error above. Existing files are not a complete new release.
exit /b 1
