# syntax=docker/dockerfile:1.7

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/LiteGateway.Proxy/LiteGateway.Proxy.csproj src/LiteGateway.Proxy/
RUN dotnet restore src/LiteGateway.Proxy/LiteGateway.Proxy.csproj

COPY src/LiteGateway.Proxy/ src/LiteGateway.Proxy/
RUN dotnet publish src/LiteGateway.Proxy/LiteGateway.Proxy.csproj \
    -c Release \
    -o /app/publish \
    /p:PublishAot=false \
    /p:PublishTrimmed=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

COPY --from=build /app/publish/ ./

ENV DOTNET_EnableDiagnostics=0

EXPOSE 8080 8443 9443

ENTRYPOINT ["dotnet", "LiteGateway.Proxy.dll"]
