FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["*.csproj", "./"]
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app/publish

FROM runtime
WORKDIR /app
COPY --from=build /app/publish .

# Important: Listen on the PORT that Render provides
ENV ASPNETCORE_URLS=http://+:$PORT

ENTRYPOINT ["dotnet", "Skills.dll"]