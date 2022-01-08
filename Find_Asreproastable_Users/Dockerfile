FROM mcr.microsoft.com/dotnet/runtime:6.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["Find_Asreproastable_Users/Find_Asreproastable_Users.csproj", "Find_Asreproastable_Users/"]
RUN dotnet restore "Find_Asreproastable_Users/Find_Asreproastable_Users.csproj"
COPY . .
WORKDIR "/src/Find_Asreproastable_Users"
RUN dotnet build "Find_Asreproastable_Users.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Find_Asreproastable_Users.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Find_Asreproastable_Users.dll"]
