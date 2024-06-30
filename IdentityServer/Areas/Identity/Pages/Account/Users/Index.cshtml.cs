using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityServer.Areas.Identity.Pages.Account.User
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;

        [BindProperty]
        public IQueryable<IdentityUser> UserList { get; set; }

        public IndexModel(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
            UserList = Enumerable.Empty<IdentityUser>().AsQueryable();
        }
        public void OnGet()
        {
            UserList = _userManager.Users;
        }
    }
}
