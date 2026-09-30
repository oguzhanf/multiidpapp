using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Core.Infrastructure;
using Microsoft.AspNetCore.Mvc.Filters;

namespace MultiIdpApp.Identity;

public sealed class SignInAntiforgeryFilter : IAlwaysRunResultFilter
{
    public void OnResultExecuting(ResultExecutingContext context)
    {
        if (context.Result is IAntiforgeryValidationFailedResult)
        {
            context.Result = new RedirectResult("/SignIn");
        }
    }

    public void OnResultExecuted(ResultExecutedContext context) { }
}
