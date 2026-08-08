# syntax=docker/dockerfile:1.7
# TEST-ONLY DAST component. See infra/dast/docker-compose.dast.yml.
# NOTE: this is the one component that is allowed NOT to be distroless-chiseled
# (it is never near production traffic); it still runs as a non-root user.
FROM mcr.microsoft.com/dotnet/sdk:10.0.302-noble AS build
WORKDIR /src

COPY Directory.Build.props ./
COPY Directory.Packages.props ./
COPY global.json ./
COPY .editorconfig ./
COPY src ./src
COPY samples ./samples
COPY infra/dast/auth-proxy ./infra/dast/auth-proxy

RUN dotnet restore --locked-mode infra/dast/auth-proxy/Sentinel.Dast.AuthProxy.csproj

RUN dotnet publish infra/dast/auth-proxy/Sentinel.Dast.AuthProxy.csproj \
    -c Release \
    -o /app/publish \
    --no-restore \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0.10-noble-chiseled AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_EnableDiagnostics=0

COPY --from=build /app/publish ./

USER app
EXPOSE 8080
ENTRYPOINT ["dotnet", "Sentinel.Dast.AuthProxy.dll"]