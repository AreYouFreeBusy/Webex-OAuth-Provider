//  Copyright 2021 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;

namespace Owin.Security.Providers.Webex
{
    public static class WebexAuthenticationExtensions
    {
        public static IAppBuilder UseWebexAuthentication(this IAppBuilder app, WebexAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException("app");
            if (options == null) throw new ArgumentNullException("options");

            app.Use(typeof(WebexAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseWebexAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseWebexAuthentication(new WebexAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}