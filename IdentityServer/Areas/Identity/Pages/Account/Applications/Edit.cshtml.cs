using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Areas.Identity.Pages.Account.Applications
{
    public class EditModel : PageModel
    {
        private IOpenIddictApplicationManager _appManager;
        private ILogger<EditModel> _logger;

        public EditModel(IOpenIddictApplicationManager appManager, ILogger<EditModel> logger)
        {
            _appManager = appManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public class InputModel
        {
            [Required]
            public string? ClientId { get; set; }
            [Required]
            public string? DisplayName { get; set; }

            public string RedirectUris { get; set; } = @"https://localhost/signin-oidc";

            public string LogoutUris { get; set; } = @"https://localhost/signout-callback-oidc";
        }

        public async Task<IActionResult> OnGetAsync(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var client = await _appManager.FindByClientIdAsync(id);
            if (client == null)
            {
                return NotFound();
            }

            // Populate the form with existing data
            Input.ClientId = await _appManager.GetClientIdAsync(client);
            Input.DisplayName = await _appManager.GetDisplayNameAsync(client) ?? string.Empty;

            // Get redirect URIs
            var redirectUris = await _appManager.GetRedirectUrisAsync(client);
            Input.RedirectUris = redirectUris.FirstOrDefault()?.ToString() ?? string.Empty;

            // Get post logout redirect URIs
            var logoutUris = await _appManager.GetPostLogoutRedirectUrisAsync(client);
            Input.LogoutUris = logoutUris.FirstOrDefault()?.ToString() ?? string.Empty;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                var client = await _appManager.FindByClientIdAsync(id);

                if (client != null)
                {
                    var descriptor = new OpenIddictApplicationDescriptor();
                    await _appManager.PopulateAsync(descriptor, client);

                    // Update properties
                    descriptor.DisplayName = Input.DisplayName;
                    descriptor.RedirectUris.Clear();
                    descriptor.RedirectUris.Add(new Uri(Input.RedirectUris));
                    descriptor.PostLogoutRedirectUris.Clear();
                    descriptor.PostLogoutRedirectUris.Add(new Uri(Input.LogoutUris));

                    // Ensure permissions are set
                    descriptor.Permissions.Clear();
                    descriptor.Permissions.UnionWith(new[]
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.EndSession,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.Prefixes.Scope + "api",
                        Permissions.Prefixes.Scope + "profile",
                        Permissions.ResponseTypes.Code
                    });

                    await _appManager.UpdateAsync(client, descriptor);

                    _logger.LogInformation("Se actualizó el Cliente {ClientId}", id);

                    return LocalRedirect("/Identity/Account/Applications/Index");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "No se encontró la aplicación.");
                }
            }

            return Page();
        }
    }
}
