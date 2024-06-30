using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace IdentityServer.Areas.Identity.Pages.Account.Applications
{
    public class DeleteModel : PageModel
    {

        private IOpenIddictApplicationManager _appManager;
        private ILogger<NewModel> _logger;

        public DeleteModel(IOpenIddictApplicationManager appManager, ILogger<NewModel> logger)
        {
            _appManager = appManager;
            _logger = logger;
        }


        [BindProperty]
        public string ClientId { get; set; } = "";
        public async Task<IActionResult> OnGetAsync(string? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var client = await _appManager.FindByClientIdAsync(id);

            if (client is null)
            {
                return NotFound();
            }

            ClientId = id;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string? ClientId)
        {
            if (ClientId == null)
            {
                return NotFound();
            }

            var client = await _appManager.FindByClientIdAsync(ClientId);

            if (client is null)
            {
                return NotFound();
            }

            await _appManager.DeleteAsync(client);

            return LocalRedirect("/Identity/Account/Applications/Index");
        }
    }
}
