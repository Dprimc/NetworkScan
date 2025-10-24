# NetworkScan

Fast IPv4 network scanner with a simple WPF GUI and a console front‑end.

- CIDR and range scanning
- High concurrency ping + port scan
- Enrichment: reverse DNS, SNMP sysName/sysDescr, HTTP Server banner
- OS heuristics (TTL + banners + ports)
- Vendor detection from MAC OUI with optional online fallback
- GUI niceties: copy IP/MAC from context menu, CSV/JSON export

## Quick start

- GUI: run `run_gui.bat` (builds Release and launches the WPF app)
- Console: `dotnet run -- --cidr 192.168.1.0/24` or `--range 192.168.1.10-192.168.1.50`

Common options:
- `--ports 22,80,443` or `--ports 1-1024`
- `--concurrency 256` and `--port-concurrency 128`
- `--timeout 250`
- `--skip-ports` for ping only

## OS and Vendor detection

- OS is inferred using TTL, SSH/HTTP banners and SNMP (best‑effort, unauthenticated).
- Vendor is derived from MAC OUI (embedded map) and, if not found, via `api.macvendors.com` with a short timeout.

## Build locally

- Requirements: .NET SDK 9 (Desktop Runtime for running GUI without `dotnet`)
- CLI: `dotnet build -c Release`
- Publish GUI: `dotnet publish NetworkScan.Gui/NetworkScan.Gui.csproj -c Release -r win-x64 -p:PublishSingleFile=true -p:SelfContained=false -o publish/gui`

## GitHub Actions (CI)

This repo includes a workflow that:
- Builds the solution on Windows
- Publishes the GUI as a single‑file app
- Uploads the artifact on every push
- When pushing a tag like `v0.1.0`, creates a GitHub Release and attaches the build

See `.github/workflows/build.yml`.

## Releasing

1. Update version in your release notes/commit message.
2. Create and push a tag, e.g.:
   - `git tag -a v0.1.0 -m "v0.1.0"`
   - `git push origin v0.1.0`
3. The workflow will publish a release with the GUI artifact.

## Notes

- Scans are best‑effort and may vary across networks and device firewalls.
- Online OUI lookups are optional and will be skipped if the service is unreachable.

