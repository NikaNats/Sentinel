# syntax=docker/dockerfile:1.7

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Directory.Build.props ./
COPY Directory.Packages.props ./
COPY global.json ./
COPY .editorconfig ./
COPY src ./src
COPY samples ./samples

RUN dotnet restore --locked-mode samples/Sentinel.Sample.MinimalApi/Sentinel.Sample.MinimalApi.csproj
RUN dotnet publish samples/Sentinel.Sample.MinimalApi/Sentinel.Sample.MinimalApi.csproj \
    -c Release \
    -o /app/publish \
    --no-restore \
    /p:PublishAot=false \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_EnableDiagnostics=0
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

USER root

COPY infra/certs/ca.crt /usr/local/share/ca-certificates/sentinel-ca.crt

RUN apt-get update && apt-get install -y ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system sentinel \
    && useradd --system --gid sentinel sentinel

COPY --from=build /app/publish ./

USER sentinel
EXPOSE 8080
ENTRYPOINT ["dotnet", "Sentinel.Sample.MinimalApi.dll"]
