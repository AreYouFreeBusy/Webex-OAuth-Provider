using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Webex_OAuth_Demo.Startup))]
namespace Webex_OAuth_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
