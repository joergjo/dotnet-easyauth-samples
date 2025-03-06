using System.Security.Claims;
using System.Text;
using EasyAuthApi.Authentication;

const string ProfileApiUsers = "1de4c055-4572-42eb-9b4b-b140ac0df59d";
const string ClaimsApiUsers = "f0852f05-5f7d-48b8-a51c-977900aaedaf";

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddAzureWebAppDiagnostics();

// Microsoft.Identity.Web does not work for Azure Container Apps -
// see https://github.com/AzureAD/microsoft-identity-web/issues/2274
// When using App Services, uncomment the following line and comment lines 12 instead.
// builder.Services.AddAuthentication().AddAppServicesAuthentication();
builder.Services.AddAuthentication().AddEasyAuth();

// Here, we are adding policies that require the user to have a specific claim.
// This is a simple way to restrict access to certain endpoints to specific groups.
// Other examples could be to check for a specific role
// .AddPolicy("RequireApplicationIdentity", policy =>
//     policy.RequireRole("access_as_application"))
// or just being authenticated.
// .AddPolicy("RequireAuthenication", policy =>
//     policy.RequireAuthenticatedUser())
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("RequireProfileApiUsers", policy =>
        policy.RequireAssertion(context => context.User.HasClaim("groups", ProfileApiUsers)))
    .AddPolicy("RequireClaimsApiUsers", policy =>
        policy.RequireAssertion(context => context.User.HasClaim("groups", ClaimsApiUsers)));

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// These endpoints can be called without any authorization from the application's perspective. 
// If such an endpoint is protected by Easy Auth and the caller does not provide a valid token, 
// Easy Auth will return 401.
app.MapGet("/healthz", () => TypedResults.Text("UP"));

app.MapGet("/headers", (HttpRequest request) => TypedResults.Json(request.Headers));

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


// This endpoint requires an authenticated user to be a member of the "Claims API" group. 
// If Easy Auth is configured, but the caller is not a member of the expected group, this 
// will return a 403.
app.MapGet("/claims", (ClaimsPrincipal principal) =>
{
    app.Logger.LogInformation("User {User} is calling /claims", principal.Identity?.Name);
    var user =
        new
        {
            Username = principal.Claims.FirstOrDefault(c => c.Type == "name")?.Value, // The name claim is the username
            Subject = principal.Identity?.Name, // The identity's name is the sub claim's value
            Roles = principal.Claims.Where(c => c.Type == "roles").Select(c => c.Value),
            Groups = principal.Claims.Where(c => c.Type == "groups").Select(c => c.Value)
        };
    return TypedResults.Json(user);
}).RequireAuthorization("RequireClaimsApiUsers");

// This endpoint requires an authenticated user to be a member of the "Profile API" group. 
// If Easy Auth is configured, but the caller is not a member of the expected group, this 
// will return a 403.
app.MapGet("/profile/{id}", (string id, ClaimsPrincipal principal) =>
{
    app.Logger.LogInformation("User {User} is calling /profile/{Id}", principal.Identity?.Name, id);
    var profile = new Dictionary<string, object?>
    {
        ["@odata.context"] = "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
        ["businessPhones"] = Array.Empty<string>(),
        ["displayName"] = "John Doe",
        ["givenName"] = "John",
        ["jobTitle"] = null,
        ["mail"] = "john.doe@example.com",
        ["mobilePhone"] = null,
        ["officeLocation"] = null,
        ["preferredLanguage"] = null,
        ["surname"] = "Doe",
        ["userPrincipalName"] = "john.doe@example.onmicrosoft.com",
        ["id"] = id
    };

    return TypedResults.Json(profile);
}).RequireAuthorization("RequireProfileApiUsers");




app.Run();