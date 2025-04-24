FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy everything
COPY . ./
# Restore as distinct layers
RUN dotnet restore
# Build and publish a release
RUN dotnet publish -o out -c Debug

# Build runtime image
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS final

# Only if this line is uncommented, do we see our intermediate sent.
RUN rm /etc/ssl/certs/*

WORKDIR /app
COPY --from=build /app/out .
EXPOSE 8087
ENTRYPOINT ["dotnet", "TestServer.dll"]
