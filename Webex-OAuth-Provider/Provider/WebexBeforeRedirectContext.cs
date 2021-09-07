//  Copyright 2017 Stefan Negritoiu. See LICENSE file for more information.

using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Webex
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the Webex OAuth 2.0 middleware
    /// </summary>
    public class WebexBeforeRedirectContext : BaseContext<WebexAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The OWIN request context</param>
        /// <param name="options">The Webex middleware options</param>
        public WebexBeforeRedirectContext(IOwinContext context, WebexAuthenticationOptions options)
            : base(context, options) 
        {
        }
    }
}
