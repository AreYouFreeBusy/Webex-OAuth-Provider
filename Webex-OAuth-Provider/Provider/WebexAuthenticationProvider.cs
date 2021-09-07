//  Copyright 2021 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Webex
{
    /// <summary>
    /// Default <see cref="IWebexAuthenticationProvider"/> implementation.
    /// </summary>
    public class WebexAuthenticationProvider : IWebexAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="WebexAuthenticationProvider"/>
        /// </summary>
        public WebexAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnBeforeRedirect = context => Task.FromResult<object>(null);
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<WebexAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<WebexReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the BeforeRedirect method is invoked.
        /// </summary>
        public Action<WebexBeforeRedirectContext> OnBeforeRedirect { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<WebexApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        /// Invoked whenever Webex successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(WebexAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(WebexReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the middleware, before the actual redirect.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        public virtual void BeforeRedirect(WebexBeforeRedirectContext context) 
        {
            OnBeforeRedirect(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the Webex 2.0 middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        public virtual void ApplyRedirect(WebexApplyRedirectContext context) 
        {
            OnApplyRedirect(context);
        }
    }
}