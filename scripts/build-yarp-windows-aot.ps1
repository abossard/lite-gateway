$ErrorActionPreference = 'Stop'

$Project = "src/LiteGateway.YarpProxy/LiteGateway.YarpProxy.csproj"
$OutputDir = "artifacts"

# Windows x64 AOT
dotnet publish $Project -c Release -r win-x64 -o "$OutputDir/win-x64"

# Windows ARM64 AOT
dotnet publish $Project -c Release -r win-arm64 -o "$OutputDir/win-arm64"
