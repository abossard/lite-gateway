# ============================================================================
# Stage 1: Build — Native AOT publish for linux-x64
# ============================================================================
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src

# AOT requires a native linker
RUN apt-get update && apt-get install -y --no-install-recommends clang zlib1g-dev && rm -rf /var/lib/apt/lists/*

# Restore first (layer cache)
COPY src/LiteGateway.YarpProxy/LiteGateway.YarpProxy.csproj src/LiteGateway.YarpProxy/
RUN dotnet restore src/LiteGateway.YarpProxy/LiteGateway.YarpProxy.csproj \
    -r linux-${TARGETARCH}

# Publish with Native AOT
COPY src/LiteGateway.YarpProxy/ src/LiteGateway.YarpProxy/
RUN dotnet publish src/LiteGateway.YarpProxy/LiteGateway.YarpProxy.csproj \
    -c Release \
    -r linux-${TARGETARCH} \
    -o /app/publish

# ============================================================================
# Stage 2: Runtime — chiseled (distroless) base, non-root, minimal surface
#   No shell, no package manager, no root — maximum security, minimum size.
# ============================================================================
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled AS runtime
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/abossard/lite-gateway
LABEL org.opencontainers.image.description="Lite Gateway — YARP Reverse Proxy with Native AOT"
LABEL org.opencontainers.image.licenses=MIT

COPY --from=build /app/publish/LiteGateway.YarpProxy ./LiteGateway.YarpProxy
COPY --from=build /app/publish/appsettings.json ./appsettings.json

ENV ASPNETCORE_URLS=http://+:8080

EXPOSE 8080

ENTRYPOINT ["/app/LiteGateway.YarpProxy"]
