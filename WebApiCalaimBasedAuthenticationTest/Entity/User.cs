
using Microsoft.AspNetCore.Identity;

namespace WebApiCalaimBasedAuthenticationTest.Entity
{
    public class User:IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
    }
}
