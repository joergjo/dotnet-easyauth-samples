using System.Security.Claims;
using System.Text;
using EasyAuthApi.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Microsoft.Identity.Web does not work for Azure Container Apps -
// see https://github.com/AzureAD/microsoft-identity-web/issues/2274
// When using App Services, uncomment the following line and comment lines
// 12 instead.
// builder.Services.AddAuthentication().AddAppServicesAuthentication();
builder.Services.AddAuthentication().AddEasyAuth();
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("RequireApplicationIdentity", policy =>
        policy.RequireRole("access_as_application"));
var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/healthz", () => TypedResults.Text("UP"));

app.MapGet("/claims", (ClaimsPrincipal principal) =>
{
    var user = new { principal.Identity?.Name, Role = principal.Claims.First(c => c.Type == "roles").Value };
    return TypedResults.Json(user);
}).RequireAuthorization("RequireApplicationIdentity");

app.MapGet("/x-ms-headers", (ClaimsPrincipal principal, HttpRequest request, bool decode = false) =>
{
    var xMsItems = new Dictionary<string, string>();
    var headers = request.Headers.Keys.Where(x => x.StartsWith("X-MS"));
    foreach (var header in headers)
    {
        if (!request.Headers.TryGetValue(header, out var values)) continue;
        
        var value = values.FirstOrDefault();
        if (decode && "X-MS-CLIENT-PRINCIPAL" == header)
        {
            var bytes = Convert.FromBase64String(value!);
            value = Encoding.GetEncoding("iso-8859-1").GetString(bytes);
        }
        xMsItems.Add(header, value!);
        app.Logger.LogDebug("Found {Header} with value {Value}", header, value);
    }
    return TypedResults.Json(xMsItems);
});

app.MapGet("/headers", (HttpRequest request) => TypedResults.Json(request.Headers));

app.Run();