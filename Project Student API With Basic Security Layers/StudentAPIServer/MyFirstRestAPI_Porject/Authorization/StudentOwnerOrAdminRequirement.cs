using Microsoft.AspNetCore.Authorization;

namespace StudentApi.Authorization
{
    public class StudentOwnerOrAdminRequirement : IAuthorizationRequirement
    {
    }
}
