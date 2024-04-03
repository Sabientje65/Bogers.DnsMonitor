FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base

FROM build AS build

WORKDIR /src

COPY . .
RUN dotnet restore
RUN dotnet build -c Release -o /app

# move build artifacts to app
FROM base
WORKDIR /app
COPY --from=build ./app .  

ENTRYPOINT ["dotnet", "Bogers.DnsMonitor"]