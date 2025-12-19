using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Areas.Identity.Pages.Account.Applications
{
    public class NewModel : PageModel
    {
        private IOpenIddictApplicationManager _appManager;
        private ILogger<NewModel> _logger;

        public NewModel(IOpenIddictApplicationManager appManager, ILogger<NewModel> logger)
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
            [Required]
            [StringLength(100, ErrorMessage = "El {0} debe tener  al menos {2} y un m�ximo {1} caracteres de longitud.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string? ClientSecret { get; set; }
            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("ClientSecret", ErrorMessage = "El password y la confirmaci�n no coinciden.")]
            public string? ConfirmSecret { get; set; }

        }
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            //returnUrl ??= Url.Content("~/");
            if (ModelState.IsValid)
            {
                //var app = CreateApp(Input.ClientId, Input.DisplayName, Input.ClientSecret, Input.RedirectUris);
                
                //app.ClientId = Input.ClientId;
                //app.DisplayName = Input.DisplayName;
                //app.ClientSecret = Input.ClientSecret;
                //app.RedirectUris = { new Uri(Input.RedirectUris)}
                
               
                if (string.IsNullOrEmpty(Input.ClientId))
                {
                    ModelState.AddModelError(string.Empty, "Client ID cannot be empty");
                    return Page();
                }

                var client = await _appManager.FindByClientIdAsync(Input.ClientId);
                       
               
                if(client is null)
                { 
                    var result = await _appManager.CreateAsync(new OpenIddictApplicationDescriptor
                        {
                            ClientId = Input.ClientId,
                            ClientSecret = Input.ClientSecret,
                            DisplayName = Input.DisplayName,
                            RedirectUris = { new Uri(Input.RedirectUris) },
                            PostLogoutRedirectUris = { new Uri(Input.LogoutUris) },
                            Permissions =
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
                            }
                        }

                     );
                    
                    if (result != null)
                    {
                        _logger.LogInformation("Se creo el Cliente ");

                        return LocalRedirect("/Identity/Account/Applications/Index");
                    }
                }
                
            }

            return Page();

        }


       
    }
}
