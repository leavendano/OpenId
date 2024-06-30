using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace IdentityServer.Areas.Identity.Pages.Account.Application
{
    public class IndexModel : PageModel
    {
        private IOpenIddictApplicationManager _appManager;

        public record AppItem(string ClientId, string ApplicationName);

        [BindProperty]
        public List<AppItem> ApplicationList { get; set; }

        public IndexModel(IOpenIddictApplicationManager appManager)
        {
            _appManager = appManager;
            ApplicationList = new List<AppItem>();
        }
        public async Task OnGetAsync()
        {
            await foreach (var application in _appManager.ListAsync())
            {
                ApplicationList.Add(new AppItem(await _appManager.GetClientIdAsync(application), await _appManager.GetDisplayNameAsync(application)));
            }
        }
    }
}
