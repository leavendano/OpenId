using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace IdentityServer.Areas.Identity.Pages.Account.Application
{
    public class IndexModel(IOpenIddictApplicationManager appManager) : PageModel
    {
        private IOpenIddictApplicationManager _appManager = appManager;

        public record AppItem(string ClientId, string ApplicationName);

        [BindProperty]
        public List<AppItem> ApplicationList { get; set; } = [];

        public async Task OnGetAsync()
        {
            await foreach (var application in _appManager.ListAsync())
            {
                var clientId = await _appManager.GetClientIdAsync(application) ?? "";
                var displayName = await _appManager.GetDisplayNameAsync(application) ?? "";
                ApplicationList.Add(new AppItem(clientId, displayName));
            }
        }
    }
}
