FROM mcr.microsoft.com/dotnet/sdk:11.0-preview AS build
WORKDIR /src

COPY Sentinel.sln ./
COPY src/Sentinel/Sentinel.csproj src/Sentinel/
RUN dotnet restore Sentinel.sln

COPY . .
RUN dotnet publish src/Sentinel/Sentinel.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:11.0-preview AS final
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "Sentinel.dll"]
