using Microsoft.AspNetCore.Authentication;

namespace EasyAuthApi.Authentication;

public static class EasyAuthAuthenticationAppBuilderExtensions
{
    public static AuthenticationBuilder AddEasyAuth(
        this AuthenticationBuilder builder,
        string authenticationScheme = EasyAuthAuthenticationDefaults.AuthenticationScheme,
        Action<AuthenticationSchemeOptions>? configureOptions = null) 
        => builder.AddScheme<AuthenticationSchemeOptions, EasyAuthAuthenticationHandler>(
            authenticationScheme, 
            configureOptions);
}