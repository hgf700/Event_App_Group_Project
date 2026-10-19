FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# 1. Kopiujemy tylko pliki .csproj (lepsze cache'owanie)
COPY Backend/Backend.csproj Backend/
COPY EventApp.Domain/EventApp.Domain.csproj EventApp.Domain/
COPY EventApp.Infrastructure/EventApp.Infrastructure.csproj EventApp.Infrastructure/
COPY EventApp.Services/EventApp.Services.csproj EventApp.Services/

# 2. Restore tylko głównego projektu (pociągnie resztę)
RUN dotnet restore Backend/Backend.csproj

# 3. Kopiujemy resztę kodu
COPY . .

# 4. Publish
RUN dotnet publish Backend/Backend.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

COPY --from=build /app/publish .

EXPOSE 8080
ENTRYPOINT ["dotnet", "Backend.dll"]