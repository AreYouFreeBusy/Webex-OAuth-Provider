//  Copyright 2021 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Webex
{
    /// <summary>
    /// Specifies callback methods which the <see cref="WebexAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IWebexAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever Webex successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(WebexAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(WebexReturnEndpointContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the middleware, before the actual redirect.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void BeforeRedirect(WebexBeforeRedirectContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the Webex middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void ApplyRedirect(WebexApplyRedirectContext context);
    }
}