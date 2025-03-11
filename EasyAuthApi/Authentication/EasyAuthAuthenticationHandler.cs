using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace EasyAuthApi.Authentication;

public class EasyAuthAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private const string NameType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
    private const string RoleType = "roles";

    public EasyAuthAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder) : base(options, loggerFactory, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-MS-CLIENT-PRINCIPAL", out var principalHeaderValue) ||
            !Request.Headers.TryGetValue("X-MS-CLIENT-PRINCIPAL-IDP", out var idpHeaderValue))
            return Task.FromResult(AuthenticateResult.NoResult());

        if (principalHeaderValue.FirstOrDefault() is not { } encodedPrincipal ||
            idpHeaderValue.FirstOrDefault() is not { } idp) 
            return Task.FromResult(AuthenticateResult.NoResult());
            
        var bytes = Convert.FromBase64String(encodedPrincipal);
        var json = Encoding.GetEncoding("iso-8859-1").GetString(bytes);
        var document = JsonDocument.Parse(json);
        var claimsElement = document.RootElement.GetProperty("claims").EnumerateArray();
        var claims = claimsElement.Select(e => new Claim(
            e.GetProperty("typ").GetString()!, 
            e.GetProperty("val").GetString()!,
            ClaimValueTypes.String,
            idp));
        var identity = new ClaimsIdentity(
            claims, 
            Scheme.Name, 
            NameType, 
            RoleType);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
