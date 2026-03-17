# Example YARP Configuration

This directory contains the example `yarp.json` mounted into the Docker container
as `/app/config.json`. It demonstrates header forwarding — the core use case of
Lite Gateway.

## How it works

The `yarp.json` file configures a catch-all route that:
1. Matches every incoming request (`{**catch-all}`)
2. Injects `X-Custom-Header: my-value` via a request transform
3. Forwards to the backend cluster

## Configuration approaches

### 1. Mounted config file (this approach)

```bash
docker compose up --build
# yarp.json is mounted as /app/config.json
```

### 2. Environment variables (YARP native)

```bash
docker run \
  -e ReverseProxy__Clusters__upstream__Destinations__default__Address=http://backend:3000 \
  -e ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader=X-Custom-Header \
  -e ReverseProxy__Routes__catch-all__Transforms__0__Set=my-value \
  -p 8080:8080 lite-gateway
```

### 3. `PROXY_HEADER_*` shorthand

```bash
docker run \
  -e PROXY_HEADER_X_CUSTOM_HEADER=my-value \
  -e ReverseProxy__Clusters__upstream__Destinations__default__Address=http://backend:3000 \
  -p 8080:8080 lite-gateway
```

Underscores in the env var name become hyphens in the header:
`PROXY_HEADER_X_CUSTOM_HEADER` → `X-Custom-Header: my-value`
