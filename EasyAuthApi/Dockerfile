FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG TARGETARCH
WORKDIR "/src"
COPY ["EasyAuthApi/EasyAuthApi.csproj", "EasyAuthApi/"]
RUN dotnet restore "EasyAuthApi/EasyAuthApi.csproj" -a $TARGETARCH 
COPY [".", "."]
WORKDIR "/src/EasyAuthApi"
RUN dotnet publish "EasyAuthApi.csproj" -a $TARGETARCH --no-restore -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "EasyAuthApi.dll"]
