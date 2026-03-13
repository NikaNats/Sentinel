# Build stage
FROM mcr.microsoft.com/dotnet/sdk:11.0-preview AS build
WORKDIR /src

# Restore with lock-file enforcement for deterministic dependencies.
COPY ["Sentinel.sln", "./"]
COPY ["src/Sentinel/Sentinel.csproj", "src/Sentinel/"]
RUN dotnet restore "Sentinel.sln" --locked-mode

# Copy source and publish.
COPY . .
RUN dotnet publish "src/Sentinel/Sentinel.csproj" \
	-c Release \
	-o /app/publish \
	--no-restore \
	-p:UseAppHost=false

# Runtime stage (rootless).
FROM mcr.microsoft.com/dotnet/aspnet:11.0 AS final
WORKDIR /app

EXPOSE 8080
EXPOSE 8443

COPY --from=build /app/publish .

USER 1654

ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_EnableDiagnostics=0

# Kubernetes guidance:
# securityContext:
#   readOnlyRootFilesystem: true
#   allowPrivilegeEscalation: false

ENTRYPOINT ["dotnet", "Sentinel.dll"]
