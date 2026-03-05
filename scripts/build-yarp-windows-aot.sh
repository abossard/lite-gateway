#!/usr/bin/env bash
set -euo pipefail

PROJECT="src/LiteGateway.YarpProxy/LiteGateway.YarpProxy.csproj"
OUTPUT_DIR="artifacts"

# Windows x64 AOT
dotnet publish "$PROJECT" \
  -c Release \
  -r win-x64 \
  -o "$OUTPUT_DIR/win-x64"

# Windows ARM64 AOT
dotnet publish "$PROJECT" \
  -c Release \
  -r win-arm64 \
  -o "$OUTPUT_DIR/win-arm64"
