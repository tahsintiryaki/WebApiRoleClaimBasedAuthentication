using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.Design;
using System.Security.Claims;
using System.Net;
using Microsoft.JSInterop;
using WebApiCalaimBasedAuthenticationTest.ResponseModel;

namespace WebApiCalaimBasedAuthenticationTest.ActionFilter
{

    public class CheckPermissionActionFilter : IAsyncActionFilter
    {

        private readonly IHttpContextAccessor _httpContextAccessor;


        public CheckPermissionActionFilter(IHttpContextAccessor httpContextAccessor = null)
        {

            _httpContextAccessor = httpContextAccessor;

        }
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {

           var token =  _httpContextAccessor.HttpContext.Request.Headers["Authorization"];
            
            if (!string.IsNullOrEmpty(token))
            {
                var controllerName = context.RouteData.Values["controller"];
                var actionName = context.RouteData.Values["action"];
                var sum = controllerName + "/" + actionName;
              
                var userClaims = context.HttpContext.User.Claims.ToList();
                if(userClaims.Any(t => t.Type == sum))
                {
                    await next();
                }
                else
                {
                   
                    context.Result = new BadRequestObjectResult(HttpStatusCode.Forbidden);
                    return;
                }
               

            }
            else
            {

            }


        }
    }

}
