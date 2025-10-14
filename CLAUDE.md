# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an **OpenID Connect Identity Server** built with ASP.NET Core 8.0 using OpenIddict for OAuth 2.0 and OpenID Connect implementation. The server provides authentication and authorization services with ASP.NET Core Identity for user management and PostgreSQL as the database backend.

## Technology Stack

- **.NET 8.0** (SDK version 8.0.403 specified in global.json)
- **OpenIddict 5.6.0** - OpenID Connect server framework
- **ASP.NET Core Identity** - User authentication and authorization
- **Entity Framework Core 8.0** with PostgreSQL (Npgsql)
- **Serilog** - Structured logging
- **Razor Pages** - UI pages for Identity management

## Build and Run Commands

```bash
# Build the solution
dotnet build IdentityServer.sln

# Run the application (from IdentityServer directory)
cd IdentityServer
dotnet run

# Apply database migrations
dotnet ef database update --project IdentityServer

# Create new migration
dotnet ef migrations add <MigrationName> --project IdentityServer

# Restore packages
dotnet restore
```

## Application Configuration

The application runs on:
- **HTTP**: http://0.0.0.0:7002
- **HTTPS**: https://0.0.0.0:7001

Configuration is in [appsettings.json](IdentityServer/appsettings.json):
- Database connection uses PostgreSQL via `PostgresConnection` connection string
- Serilog logs to console and daily rolling files in `./log/OpenId_.txt`
- Command timeout for database operations is configurable via `CommandTimeout` setting

## Architecture

### Database and Identity

- **ApplicationDbContext** ([Data/ApplicationDbContext.cs](IdentityServer/Data/ApplicationDbContext.cs)) extends `IdentityDbContext<IdentityUser>`
- Uses **snake_case naming convention** for PostgreSQL tables via `UseSnakeCaseNamingConvention()`
- Seeds two default roles: "Admin" and "User"
- Database is auto-created on startup via `EnsureCreatedAsync()` in [Program.cs](IdentityServer/Program.cs)

### OpenIddict Configuration

The OpenID Connect server is configured in [Program.cs](IdentityServer/Program.cs:34-75):

**Supported OAuth 2.0 flows:**
- Authorization Code Flow with PKCE (required)
- Client Credentials Flow
- Refresh Token Flow

**Endpoints:**
- `/connect/authorize` - Authorization endpoint
- `/connect/token` - Token endpoint
- `/connect/userinfo` - UserInfo endpoint
- `/connect/logout` - Logout endpoint

**Registered Scopes:**
- `api` - API access scope
- `profile` - Profile information scope

**Security Note:** The application uses ephemeral encryption and signing keys (`AddEphemeralEncryptionKey()` and `AddEphemeralSigningKey()`). For production, replace these with persistent keys stored securely.

### Authorization Controller

[AuthorizationController.cs](IdentityServer/Controllers/AuthorizationController.cs) handles all OpenID Connect protocol endpoints:

- **Authorize** (GET/POST `/connect/authorize`) - Handles authorization requests, authenticates users, and issues authorization codes
- **Exchange** (POST `/connect/token`) - Token endpoint that handles:
  - Client credentials grant
  - Authorization code grant
  - Refresh token grant
- **Userinfo** (GET `/connect/userinfo`) - Returns user claims
- **Logout** (GET `/connect/logout`) - Signs out users

Claims are configured with destinations to control which tokens include specific claims (access token vs identity token).

### Seeding and Initialization

On startup, [Program.cs](IdentityServer/Program.cs:130-192) seeds:

1. **Default OAuth Client:**
   - Client ID: `polaris_cv`
   - Display Name: "Polaris"
   - Redirect URI: `https://localhost:7003/signin-oidc`
   - Post-logout URI: `https://localhost:7003/signout-callback-oidc`
   - Granted permissions: authorization code flow, client credentials, refresh tokens, api and profile scopes

2. **Default Admin User:**
   - Username: "ADMINISTRADOR"
   - Email: administrador@ecsmexico.com
   - Role: Admin
   - Custom claims: Username and Role claims

### Areas Structure

The application uses ASP.NET Core Areas for organizing Identity UI:

- **Areas/Identity/Pages/Account/** - Identity management pages:
  - **Applications/** - Manage OAuth client applications (New, Edit, Delete, Index)
  - **Users/** - User management (Index, Edit)
  - **Roles/** - Role management (Index, New, Edit)
  - **Manage/** - User self-service (SetPassword, etc.)
  - Login, Register pages

### Password Policy

Password requirements are configured in [Program.cs](IdentityServer/Program.cs:81-90):
- Requires digit, lowercase, uppercase, non-alphanumeric character
- Minimum length: 6 characters
- Required unique characters: 1
- Email confirmation is disabled (`RequireConfirmedAccount = false`)

## Database Migrations

Migrations are stored in `Data/Migrations/` directory. The application uses PostgreSQL-specific features via Npgsql provider and applies snake_case naming convention to all database objects.

## Static Assets

The application includes a complete UI theme in `wwwroot/assets/`:
- Custom CSS and JavaScript for admin interface
- Various vendor libraries (jQuery, DataTables, ApexCharts, etc.)
- Icon fonts and image assets
