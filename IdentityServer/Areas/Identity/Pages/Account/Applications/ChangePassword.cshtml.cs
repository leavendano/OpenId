using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Areas.Identity.Pages.Account.Applications
{
    public class ChangePasswordModel : PageModel
    {
        private IOpenIddictApplicationManager _appManager;
        private ILogger<ChangePasswordModel> _logger;

        public ChangePasswordModel(IOpenIddictApplicationManager appManager, ILogger<ChangePasswordModel> logger)
        {
            _appManager = appManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public string? ClientId { get; set; }
        public string? DisplayName { get; set; }

        public class InputModel
        {
            [Required]
            [StringLength(100, ErrorMessage = "El {0} debe tener al menos {2} y un máximo {1} caracteres de longitud.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Nuevo Password")]
            public string? ClientSecret { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirmar Password")]
            [Compare("ClientSecret", ErrorMessage = "El password y la confirmación no coinciden.")]
            public string? ConfirmSecret { get; set; }
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

            ClientId = await _appManager.GetClientIdAsync(client);
            DisplayName = await _appManager.GetDisplayNameAsync(client);

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

                    // Update only the client secret
                    descriptor.ClientSecret = Input.ClientSecret;

                    await _appManager.UpdateAsync(client, descriptor);

                    _logger.LogInformation("Se actualizó el password del Cliente {ClientId}", id);

                    return LocalRedirect("/Identity/Account/Applications/Index");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "No se encontró la aplicación.");
                }
            }

            // If we got here, reload the client info
            var clientReload = await _appManager.FindByClientIdAsync(id);
            if (clientReload != null)
            {
                ClientId = await _appManager.GetClientIdAsync(clientReload);
                DisplayName = await _appManager.GetDisplayNameAsync(clientReload);
            }

            return Page();
        }
    }
}
