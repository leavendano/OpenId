using System.Security.Claims;
using IdentityServer.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Serilog;
using static OpenIddict.Abstractions.OpenIddictConstants;


Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{

    var builder = WebApplication.CreateBuilder(args);
    // Add Serilog 
    builder.Host.UseSerilog((_, config) => config.ReadFrom.Configuration(builder.Configuration));

    // Add services to the container.
    var connectionString = builder.Configuration.GetConnectionString("PostgresConnection");
    // Add timeoud to db
_ = int.TryParse(builder.Configuration["CommandTimeout"] ?? "60", out int CommandTimeout);
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(connectionString);
   
    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();

});

builder.Services.AddOpenIddict()

    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the EF Core stores/models.
        options
            .UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        options
            .AllowClientCredentialsFlow()
            .AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();

        options.SetLogoutEndpointUris("/connect/logout")
            .SetTokenEndpointUris("/connect/token")
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetUserinfoEndpointUris("/connect/userinfo");

        // Encryption and signing of tokens
        options
            .AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey()
            .DisableAccessTokenEncryption();

        // Register scopes (permissions)
        options.RegisterScopes("api");
        options.RegisterScopes("profile");

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            .EnableTokenEndpointPassthrough()
            .EnableAuthorizationEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .EnableLogoutEndpointPassthrough();
    });

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.Configure<IdentityOptions>(options =>
{
    // Default Password settings.
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;
});

// Configure Razor Pages with authorization
builder.Services.AddRazorPages(options =>
{
    // Require authentication for all pages in Areas/Identity/Pages
    options.Conventions.AuthorizeAreaFolder("Identity", "/");

    // Allow anonymous access to Login and Register pages
    options.Conventions.AllowAnonymousToAreaPage("Identity", "/Account/Login");
    options.Conventions.AllowAnonymousToAreaPage("Identity", "/Account/Register");
    options.Conventions.AllowAnonymousToAreaPage("Identity", "/Account/ForgotPassword");
    options.Conventions.AllowAnonymousToAreaPage("Identity", "/Account/ResetPassword");
});

builder.Services.AddControllers();
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();


await SeedDefaultClients();

app.Run();






async Task SeedDefaultClients()
{
    using var scope = app.Services.CreateScope();

    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

    await context.Database.EnsureCreatedAsync();

    var client = await manager.FindByClientIdAsync("polaris_cv");

    if (client is null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "polaris_cv",
            ClientSecret = "CON030626vol@",
            DisplayName = "Polaris",
            RedirectUris = { new Uri("https://localhost:7003/signin-oidc") },
            PostLogoutRedirectUris = { new Uri("https://localhost:7003/signout-callback-oidc") },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.Logout,

                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.ClientCredentials,
                Permissions.GrantTypes.RefreshToken,

                Permissions.Prefixes.Scope + "api",
                Permissions.Prefixes.Scope + "profile",
                Permissions.ResponseTypes.Code
            }
        });
    }

    //var userx = await userManager.FindByLoginAsync("Administrador","CON030626vol@");
    var user = await userManager.FindByNameAsync("Administrador");
    if(user is null)
    {
            IdentityUser newUser = new IdentityUser
        {
            UserName = "ADMINISTRADOR",
            Email = "administrador@ecsmexico.com",
            EmailConfirmed = true
        };
        
        IdentityResult result =  userManager.CreateAsync(newUser, "CON030626vol@").Result;
        var temp2 = userManager.AddClaimsAsync(newUser, new Claim[] {
                new Claim(OpenIddictConstants.Claims.Username,newUser.UserName),
                new Claim(OpenIddictConstants.Claims.Role, "Admin"),
            }).Result;

        if (result.Succeeded)
        {
            userManager.AddToRoleAsync(newUser, "Admin").Wait();
        }
    }
    
}

}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}