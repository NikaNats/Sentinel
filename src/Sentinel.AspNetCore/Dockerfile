# syntax=docker/dockerfile:1.7

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
# Stage 2: High-Assurance Secure Runtime (Chiseled)
# ==========================================
FROM mcr.microsoft.com/dotnet/aspnet:10.0.10-noble-chiseled AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_EnableDiagnostics=0
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

# Copy the securely assembled CA certificate bundle from the build stage
# Chiseled images have no shell, but these files are automatically resolved by the .NET runtime during connection
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the compiled application
COPY --from=build /app/publish ./

# Chiseled images include a pre-configured non-privileged user "app" (UID 1654)
# No root privileges or root copying operations occur here
USER app
EXPOSE 8080
ENTRYPOINT ["dotnet", "Sentinel.Sample.MinimalApi.dll"]
