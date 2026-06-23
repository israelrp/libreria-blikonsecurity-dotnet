using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;


namespace DemoAPIWithSecurity.Auth
{

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class CustomAuthorizeAttribute : AuthorizeAttribute, IAuthorizationRequirement, IAuthorizationRequirementData
    {
        // Esta propiedad guardará el permiso que le pases en el controlador, ej: "products:read"
        public string? Permission { get; }

        public CustomAuthorizeAttribute(string? permission = null)
        {
            Permission = permission;
        }

        // Este es el contrato de .NET 9 (IAuthorizationRequirementData).
        // Le dice al framework: "Yo mismo soy el requerimiento que el Handler debe evaluar".
        public IEnumerable<IAuthorizationRequirement> GetRequirements()
        {
            yield return this;
        }
    }
}