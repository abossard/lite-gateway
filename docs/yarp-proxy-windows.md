# Lite Gateway — Windows Deployment Guide

A step-by-step guide for building, configuring, and running **Lite Gateway**
as a native Windows application. All examples use **PowerShell** and Windows-native tooling.

> **What is this?** A lightweight, high-performance reverse proxy built on
> [YARP](https://microsoft.github.io/reverse-proxy/) with Native AOT compilation.
> It forwards HTTP requests to a backend and can inject custom headers — all without
> writing any proxy code. Configuration is 100% declarative via a simple `config.json`.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Build from Source](#build-from-source)
3. [Run the Proxy](#run-the-proxy)
4. [Startup Banner](#startup-banner)
5. [Configuration](#configuration)
   - [Method 1: JSON Config File (Recommended)](#method-1-json-config-file-recommended)
   - [Method 2: Environment Variables (YARP Native)](#method-2-environment-variables-yarp-native)
   - [Method 3: PROXY_HEADER_* Shorthand](#method-3-proxy_header-shorthand)
6. [Header Injection Examples](#header-injection-examples)
7. [Run as a Windows Service](#run-as-a-windows-service)
8. [Run Behind IIS (Reverse Proxy)](#run-behind-iis-reverse-proxy)
9. [Firewall & Port Configuration](#firewall--port-configuration)
10. [Troubleshooting](#troubleshooting)
11. [Quick Reference Card](#quick-reference-card)

---

## Prerequisites

| Requirement | How to Install |
| --- | --- |
| **.NET 10 SDK** | `winget install Microsoft.DotNet.SDK.10` or download from [dot.net](https://dot.net) |
| **Visual Studio Build Tools** *(AOT only)* | `winget install Microsoft.VisualStudio.2022.BuildTools` — include "Desktop development with C++" workload |
| **Git** *(optional)* | `winget install Git.Git` |

> **💡 Tip:** The Visual Studio Build Tools are required only for **Native AOT** compilation.
> If you just want to run the proxy in development mode (`dotnet run`), the .NET SDK alone is enough.

Verify your setup:

```powershell
dotnet --version    # Should show 10.0.xxx
```

---

## Build from Source

### Clone the Repository

```powershell
git clone https://github.com/your-org/lite-gateway.git
cd lite-gateway
```

### Development Build (JIT, fast compile)

```powershell
dotnet run --project src\LiteGateway.YarpProxy\LiteGateway.YarpProxy.csproj
```

The proxy starts at `http://localhost:8080`.

### Release Build — Native AOT (recommended for production)

Native AOT produces a **single self-contained `.exe`** (~15–25 MB) with no .NET runtime dependency.

```powershell
# Windows x64
dotnet publish src\LiteGateway.YarpProxy\LiteGateway.YarpProxy.csproj `
    -c Release -r win-x64 -o artifacts\win-x64

# Windows ARM64
dotnet publish src\LiteGateway.YarpProxy\LiteGateway.YarpProxy.csproj `
    -c Release -r win-arm64 -o artifacts\win-arm64
```

Or use the included script:

```powershell
.\scripts\build-yarp-windows-aot.ps1
```

The output is a single file:

```
artifacts\win-x64\LiteGateway.YarpProxy.exe     # ~15–25 MB, zero dependencies
artifacts\win-arm64\LiteGateway.YarpProxy.exe
```

> **📦 Prebuilt Binaries:** Check the [Releases](../../releases) page for ready-to-use
> Windows x64 and ARM64 binaries built by CI.

---

## Run the Proxy

### Quick Start

```powershell
# Run the compiled binary (looks for config.json in current directory)
.\LiteGateway.YarpProxy.exe

# Or specify a config file explicitly
.\LiteGateway.YarpProxy.exe --config C:\path\to\config.json

# Short form
.\LiteGateway.YarpProxy.exe -c .\my-config.json
```

The proxy listens on `http://localhost:8080` by default and forwards all requests
to the upstream defined in your `config.json` (or `http://localhost:5000` from the
built-in `appsettings.json` defaults).

### Change the Listening Port

```powershell
$env:ASPNETCORE_URLS = "http://+:9090"
.\LiteGateway.YarpProxy.exe
```

### Change the Upstream Backend

```powershell
$env:ReverseProxy__Clusters__upstream__Destinations__default__Address = "http://my-backend:3000"
.\LiteGateway.YarpProxy.exe
```

### Verify It Works

Open a second PowerShell window:

```powershell
# Simple test (backend must be running)
Invoke-RestMethod -Uri http://localhost:8080/api/test -Method Post `
    -ContentType "application/json" -Body '{"hello":"world"}'

# Or with curl
curl.exe http://localhost:8080/api/test -d '{"hello":"world"}' -H "Content-Type: application/json"
```

---

## Startup Banner

When Lite Gateway starts, it prints a banner summarizing the active configuration.
This makes it easy to verify settings at a glance — especially useful when
debugging environment variable overrides or config file issues.

```
╔══════════════════════════════════════════════════════════════╗
║                      Lite Gateway                           ║
╠══════════════════════════════════════════════════════════════╣
║  Config file : C:\LiteGateway\config.json                   ║
║  Listening   : http://+:8080                                ║
║  Upstream    : https://api.acme-corp.internal:443           ║
║  Headers     : X-Tenant-ID: acme-corp                       ║
║              : X-Forwarded-By: lite-gateway-v1              ║
╠══════════════════════════════════════════════════════════════╣
║  ⚠ Health check enabled (interval: 30s)                    ║
╚══════════════════════════════════════════════════════════════╝
```

The banner shows:
- **Config file** — the resolved path to the config file in use (`config.json` in CWD or the `--config` override)
- **Listening** — the bound URL(s)
- **Upstream** — the destination backend address(es)
- **Headers** — any injected headers (from JSON config or `PROXY_HEADER_*` env vars)
- **Warnings** — health check status, missing config, or other notices

> **💡 Tip:** If you see `Config file : (none)` in the banner, no `config.json` was
> found in the current directory and no `--config` flag was provided. The proxy will
> still run using environment variables and `appsettings.json` defaults.

---

## Configuration

The proxy reads configuration from three sources, in priority order (highest wins):

| Priority | Source | Hot-Reload? |
| :---: | --- | :---: |
| **4 (highest)** | `--config` CLI flag | ✅ |
| **3** | Environment variables | ❌ (restart needed) |
| **2** | `config.json` in current working directory | ✅ |
| **1 (lowest)** | `appsettings.json` (built-in defaults) | — |

### Method 1: JSON Config File (Recommended)

By default, Lite Gateway looks for **`config.json` in the current working directory**.
You can override this with the `--config` (or `-c`) flag to point to any path.

Create a `config.json` file:

```json
{
  "ReverseProxy": {
    "Routes": {
      "catch-all": {
        "ClusterId": "upstream",
        "Match": { "Path": "{**catch-all}" },
        "Transforms": [
          { "RequestHeader": "X-Tenant-ID", "Set": "customer-42" },
          { "RequestHeader": "X-Source", "Set": "yarp-gateway" }
        ]
      }
    },
    "Clusters": {
      "upstream": {
        "Destinations": {
          "default": { "Address": "http://my-backend:8080" }
        }
      }
    }
  }
}
```

Then run the proxy:

```powershell
# Option A: Place config.json in the same directory and just run
.\LiteGateway.YarpProxy.exe

# Option B: Point to a config file anywhere on disk
.\LiteGateway.YarpProxy.exe --config C:\LiteGateway\config.json
```

> **♻️ Hot-Reload:** Edit the JSON file while the proxy is running —
> YARP automatically picks up changes within seconds. No restart needed.

#### Multiple Routes Example

```json
{
  "ReverseProxy": {
    "Routes": {
      "api-route": {
        "ClusterId": "api-backend",
        "Match": { "Path": "/api/{**remainder}" },
        "Transforms": [
          { "RequestHeader": "X-Gateway", "Set": "lite-gateway" }
        ]
      },
      "static-route": {
        "ClusterId": "static-backend",
        "Match": { "Path": "/static/{**remainder}" }
      }
    },
    "Clusters": {
      "api-backend": {
        "Destinations": {
          "primary": { "Address": "http://api-server:3000" }
        }
      },
      "static-backend": {
        "Destinations": {
          "primary": { "Address": "http://cdn-server:8080" }
        }
      }
    }
  }
}
```

### Method 2: Environment Variables (YARP Native)

Set YARP configuration directly via environment variables using `__` as the path separator:

```powershell
# Set upstream address
$env:ReverseProxy__Clusters__upstream__Destinations__default__Address = "http://my-backend:8080"

# Add header transforms
$env:ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader = "X-Tenant-ID"
$env:ReverseProxy__Routes__catch-all__Transforms__0__Set = "customer-42"
$env:ReverseProxy__Routes__catch-all__Transforms__1__RequestHeader = "X-Correlation-ID"
$env:ReverseProxy__Routes__catch-all__Transforms__1__Set = "abc-123"

# Run
.\LiteGateway.YarpProxy.exe
```

To set them permanently (survives reboots):

```powershell
[System.Environment]::SetEnvironmentVariable(
    "ReverseProxy__Clusters__upstream__Destinations__default__Address",
    "http://my-backend:8080",
    "Machine"  # or "User" for current user only
)
```

### Method 3: PROXY_HEADER_* Shorthand

The simplest way to inject headers. Set `PROXY_HEADER_<NAME>=<value>` and underscores
become hyphens in the header name:

```powershell
$env:PROXY_HEADER_X_TENANT_ID = "customer-42"
$env:PROXY_HEADER_X_CORRELATION_ID = "request-abc-123"
$env:PROXY_HEADER_TEST_ID = "1234"

# Don't forget the upstream address
$env:ReverseProxy__Clusters__upstream__Destinations__default__Address = "http://my-backend:8080"

.\LiteGateway.YarpProxy.exe
```

This injects three headers on every proxied request:
- `X-Tenant-ID: customer-42`
- `X-Correlation-ID: request-abc-123`
- `TEST-ID: 1234`

---

## Header Injection Examples

### Scenario: Add Customer Identity Headers

```powershell
$env:PROXY_HEADER_X_CUSTOMER_ID = "cust-9001"
$env:PROXY_HEADER_X_ENVIRONMENT = "production"
$env:ReverseProxy__Clusters__upstream__Destinations__default__Address = "https://api.internal.example.com"
$env:ASPNETCORE_URLS = "http://+:8080"

.\LiteGateway.YarpProxy.exe
```

Every request through `http://localhost:8080/*` now includes:
```
X-Customer-ID: cust-9001
X-Environment: production
```

### Scenario: Dynamic Header from External System

Your deployment tool sets `DEVICE_SERIAL=SN-12345`. Map it to a standardized header:

```powershell
# Map external variable to PROXY_HEADER format
$env:PROXY_HEADER_X_DEVICE_SERIAL = $env:DEVICE_SERIAL   # "SN-12345"

.\LiteGateway.YarpProxy.exe
# → Injects header: X-Device-Serial: SN-12345
```

### Scenario: Full Production Config File

Save as `C:\LiteGateway\config.json`:

```json
{
  "ReverseProxy": {
    "Routes": {
      "catch-all": {
        "ClusterId": "upstream",
        "Match": { "Path": "{**catch-all}" },
        "Transforms": [
          { "RequestHeader": "X-Forwarded-By", "Set": "lite-gateway-v1" },
          { "RequestHeader": "X-Tenant-ID", "Set": "acme-corp" },
          { "RequestHeaderRemove": "Server" }
        ]
      }
    },
    "Clusters": {
      "upstream": {
        "Destinations": {
          "primary": { "Address": "https://api.acme-corp.internal:443" },
          "fallback": { "Address": "https://api-dr.acme-corp.internal:443" }
        },
        "LoadBalancingPolicy": "RoundRobin",
        "HttpClient": {
          "MaxConnectionsPerServer": 4096,
          "EnableMultipleHttp2Connections": true
        },
        "HealthCheck": {
          "Active": {
            "Enabled": true,
            "Interval": "00:00:30",
            "Timeout": "00:00:10",
            "Path": "/health"
          }
        }
      }
    }
  }
}
```

---

## Run as a Windows Service

The AOT binary can run as a native Windows Service using `sc.exe`.

### 1. Create the Service

```powershell
# Copy binary and config to a permanent location
New-Item -ItemType Directory -Force -Path C:\LiteGateway
Copy-Item .\artifacts\win-x64\LiteGateway.YarpProxy.exe C:\LiteGateway\
Copy-Item .\config.json C:\LiteGateway\config.json

# Create the Windows Service (--config points to the permanent config location)
sc.exe create "LiteGateway" `
    binPath= "C:\LiteGateway\LiteGateway.YarpProxy.exe --config C:\LiteGateway\config.json" `
    start= auto `
    displayname= "Lite Gateway Reverse Proxy"

# Set description
sc.exe description "LiteGateway" "Lite Gateway reverse proxy with header injection"
```

### 2. Configure Environment Variables for the Service

Service environment variables are set in the registry:

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LiteGateway"

# Set listening URL
New-ItemProperty -Path $regPath -Name "Environment" -PropertyType MultiString -Value @(
    "ASPNETCORE_URLS=http://+:8080",
    "PROXY_HEADER_X_TENANT_ID=customer-42",
    "ReverseProxy__Clusters__upstream__Destinations__default__Address=http://backend:3000"
) -Force
```

### 3. Start / Stop / Manage

```powershell
# Start the service
Start-Service LiteGateway

# Check status
Get-Service LiteGateway

# View logs (stdout goes to Windows Event Log)
Get-WinEvent -LogName Application -MaxEvents 20 |
    Where-Object { $_.ProviderName -like "*LiteGateway*" }

# Stop the service
Stop-Service LiteGateway

# Remove the service (when no longer needed)
sc.exe delete "LiteGateway"
```

> **💡 Tip:** For production Windows Services, consider wrapping with
> [NSSM](https://nssm.cc/) for better logging and restart handling:
> ```powershell
> nssm install LiteGateway C:\LiteGateway\LiteGateway.YarpProxy.exe --config C:\LiteGateway\config.json
> nssm set LiteGateway AppStdout C:\LiteGateway\logs\stdout.log
> nssm set LiteGateway AppStderr C:\LiteGateway\logs\stderr.log
> nssm set LiteGateway AppEnvironmentExtra "ASPNETCORE_URLS=http://+:8080"
> ```

---

## Run Behind IIS (Reverse Proxy)

Use IIS as the public-facing endpoint with YARP running behind it.

### 1. Install the ASP.NET Core Hosting Bundle

Download and install the [.NET Hosting Bundle](https://dotnet.microsoft.com/download/dotnet/10.0) on the IIS server.

### 2. Create an IIS Site

```powershell
# Create the application directory
New-Item -ItemType Directory -Force -Path C:\inetpub\LiteGateway
Copy-Item .\artifacts\win-x64\LiteGateway.YarpProxy.exe C:\inetpub\LiteGateway\
Copy-Item .\config.json C:\inetpub\LiteGateway\config.json
```

Create `C:\inetpub\LiteGateway\web.config`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
    </handlers>
    <aspNetCore processPath=".\LiteGateway.YarpProxy.exe"
                arguments="--config .\config.json"
                stdoutLogEnabled="true"
                stdoutLogFile=".\logs\stdout"
                hostingModel="OutOfProcess">
      <environmentVariables>
        <environmentVariable name="ASPNETCORE_URLS" value="http://localhost:5000" />
        <environmentVariable name="PROXY_HEADER_X_TENANT_ID" value="customer-42" />
      </environmentVariables>
    </aspNetCore>
  </system.webServer>
</configuration>
```

### 3. Create the IIS Site

```powershell
Import-Module WebAdministration

New-Website -Name "LiteGateway" `
    -PhysicalPath "C:\inetpub\LiteGateway" `
    -Port 443 -Ssl `
    -HostHeader "gateway.example.com"
```

---

## Firewall & Port Configuration

```powershell
# Allow inbound traffic on the proxy port
New-NetFirewallRule -DisplayName "Lite Gateway" `
    -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 8080

# Verify
Get-NetFirewallRule -DisplayName "Lite Gateway*" | Format-Table Name, Enabled, Action
```

To bind to port 80 or 443 without admin rights, use URL reservations:

```powershell
# Run as Administrator
netsh http add urlacl url=http://+:80/ user="NT AUTHORITY\NETWORK SERVICE"
```

---

## Troubleshooting

### Binary won't start — missing Visual C++ runtime

**Symptom:** `The application was unable to start correctly (0xc000007b)`

**Fix:** Native AOT binaries may require the Visual C++ Redistributable:
```powershell
winget install Microsoft.VCRedist.2015+.x64
```

### Port already in use

**Symptom:** `Failed to bind to address http://+:8080: address already in use`

```powershell
# Find what's using the port
netstat -ano | findstr ":8080"

# Kill the process (replace PID)
Stop-Process -Id <PID> -Force
```

### Config file not found

Lite Gateway looks for **`config.json` in the current working directory** by default.
If no config file is found and no `--config` flag is provided, the proxy runs with
environment variables and `appsettings.json` defaults only.

**Options:**
1. Place `config.json` in the directory where you run the proxy
2. Use `--config C:\path\to\config.json` to specify an explicit path
3. Use environment variables instead (Method 2 or 3)
4. Run from the project directory with `dotnet run` (uses `appsettings.json`)

> **💡 Tip:** Check the [startup banner](#startup-banner) output — the `Config file` line
> shows exactly which file was loaded (or `(none)` if no config file was found).

### Environment variables not taking effect

PowerShell `$env:` variables are session-scoped. For persistence:

```powershell
# Current user
[Environment]::SetEnvironmentVariable("PROXY_HEADER_X_TENANT_ID", "value", "User")

# Machine-wide (requires admin)
[Environment]::SetEnvironmentVariable("PROXY_HEADER_X_TENANT_ID", "value", "Machine")

# Restart the proxy after setting machine/user env vars
```

### View active configuration

Lite Gateway prints its full configuration in the [startup banner](#startup-banner)
every time it starts. For additional detail, enable Development mode:

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
.\LiteGateway.YarpProxy.exe
```

---

## Quick Reference Card

```powershell
# ── BUILD ──────────────────────────────────────────────────────────────────
dotnet publish src\LiteGateway.YarpProxy\LiteGateway.YarpProxy.csproj `
    -c Release -r win-x64 -o artifacts\win-x64

# ── RUN (default config.json in CWD) ─────────────────────────────────────
.\LiteGateway.YarpProxy.exe

# ── RUN (explicit config path) ───────────────────────────────────────────
.\LiteGateway.YarpProxy.exe --config C:\LiteGateway\config.json

# ── RUN (env vars only) ──────────────────────────────────────────────────
$env:ASPNETCORE_URLS = "http://+:8080"
$env:ReverseProxy__Clusters__upstream__Destinations__default__Address = "http://backend:3000"
$env:PROXY_HEADER_X_TENANT_ID = "customer-42"
.\LiteGateway.YarpProxy.exe

# ── TEST ──────────────────────────────────────────────────────────────────
Invoke-RestMethod http://localhost:8080/api/test -Method Post `
    -ContentType "application/json" -Body '{"hello":"world"}'

# ── WINDOWS SERVICE ───────────────────────────────────────────────────────
sc.exe create LiteGateway `
    binPath= "C:\LiteGateway\LiteGateway.YarpProxy.exe --config C:\LiteGateway\config.json" `
    start= auto
Start-Service LiteGateway
```
