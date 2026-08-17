# syntax=docker/dockerfile:1.7
#
# DAST-specific Dockerfile for sentinel-api using standard aspnet runtime
# (not chiseled) to ensure proper CA certificate trust for Keycloak JWKS fetching.
# This is ONLY for the ephemeral DAST environment.

# ==========================================
# Stage 1: Compilation and Certificate Assembly
# ==========================================
FROM mcr.microsoft.com/dotnet/sdk:10.0.302-noble AS build
WORKDIR /src

# Install CA certificate tools during the build stage
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the production Root CA certificate and update the system bundle
COPY infra/certs/ca.crt /usr/local/share/ca-certificates/sentinel-ca.crt
RUN update-ca-certificates

# Copy project files and restore dependencies
COPY Directory.Build.props ./
COPY Directory.Packages.props ./
COPY global.json ./
COPY .editorconfig ./
COPY src ./src
COPY samples ./samples

# Restore dependencies in locked mode
RUN dotnet restore --locked-mode samples/Sentinel.Sample.MinimalApi/Sentinel.Sample.MinimalApi.csproj

# Publish the application
RUN dotnet publish samples/Sentinel.Sample.MinimalApi/Sentinel.Sample.MinimalApi.csproj \
    -c Release \
    -o /app/publish \
    --no-restore \
    /p:PublishAot=false \
    /p:UseAppHost=false

# ==========================================
# Stage 2: Standard Runtime (not chiseled) for DAST
# ==========================================
FROM mcr.microsoft.com/dotnet/aspnet:10.0.11-noble AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_EnableDiagnostics=0
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

# Install ca-certificates and add our CA to the system trust store
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY infra/certs/ca.crt /usr/local/share/ca-certificates/sentinel-ca.crt
RUN update-ca-certificates

# Copy the compiled application
COPY --from=build /app/publish ./

# Point directly to the clean CA certificate. NO dummy keys needed.
ENV Security__TrustedRootCaPath=/usr/local/share/ca-certificates/sentinel-ca.crt

# Non-root user
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1
ENTRYPOINT ["dotnet", "Sentinel.Sample.MinimalApi.dll"]