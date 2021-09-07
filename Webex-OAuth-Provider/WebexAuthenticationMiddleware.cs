//  Copyright 2021 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Providers.Webex
{
    public class WebexAuthenticationMiddleware : AuthenticationMiddleware<WebexAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public WebexAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WebexAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.ClientId)) 
            {
                throw new ArgumentException("ClientId option must be provided.");
            }
            if (String.IsNullOrWhiteSpace(Options.ClientSecret)) 
            {
                throw new ArgumentException("ClientSecret option must be provided.");
            }
            _logger = app.CreateLogger<WebexAuthenticationMiddleware>();

            if (Options.Provider == null) 
            {
                Options.Provider = new WebexAuthenticationProvider();
            }
            
            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(WebexAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType)) 
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10 MB
            };
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.Webex.WebexAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<WebexAuthenticationOptions> CreateHandler()
        {
            return new WebexAuthenticationHandler(_httpClient, _logger);
        }

        private HttpMessageHandler ResolveHttpMessageHandler(WebexAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("Vaidator Handler Mismatch");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}