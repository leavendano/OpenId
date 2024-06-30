using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Areas.Identity.Pages.Account.Roles
{
    public class NewModel : PageModel
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<NewModel> _logger;

        public NewModel(RoleManager<IdentityRole> roleManager, ILogger<NewModel> logger)
        {
            _roleManager = roleManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public string ReturnUrl { get; set; }
        public class InputModel
        {
            [Required]
            public string? Name { get; set; }
            [Required]
            public string? NormalizedName { get; set; }

        }
        public void OnGet(string returnUrl = null)
        {
           ReturnUrl = returnUrl;  
        }

        public async Task<IActionResult> OnPostAsync()
        {
            //returnUrl ??= Url.Content("~/");
            if (ModelState.IsValid)
            {
                var role = CreateRole();

                role.Name = Input.Name;
                role.NormalizedName = Input.NormalizedName.ToUpper();

                var result =  await _roleManager.CreateAsync(role);
                if (result.Succeeded)
                {
                    _logger.LogInformation("Se creo el Rol ");

                    
                    return LocalRedirect("/Identity/Account/Roles/Index");
                }
                
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return Page();

        }


        private IdentityRole CreateRole()
        {
            try
            {
                return Activator.CreateInstance<IdentityRole>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(IdentityRole)}'. " +
                    $"Ensure that '{nameof(IdentityRole)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/Identity/Pages/Account/Roles/New.cshtml");
            }
        }
    }
}
