using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityServer.Areas.Identity.Pages.Account.Roles
{
    public class IndexModel : PageModel
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        [BindProperty]
        public IQueryable<IdentityRole> RolesList { get; set; }
        public IndexModel(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
            RolesList = Enumerable.Empty<IdentityRole>().AsQueryable();
        }
        public void OnGet()
        {
            RolesList = _roleManager.Roles;
        }
    }
}
