using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Identity.Web;

namespace EasyAuthWebApp.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
    }

    public List<Claim> Claims { get; set; } = [];

    public void OnGet()
    {
        if (HttpContext.User is null)
        {
            return;
        } 

        Claims = [.. User.Claims.OrderBy(c => c.Type)]; 
    }
}