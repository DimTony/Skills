using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Skills.Models;

namespace Skills.Data
{
    public static class DataSeeder
    {
        public static async Task SeedRolesAsync(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

            foreach (var roleName in Enum.GetNames(typeof(UserType)))
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    var result = await roleManager.CreateAsync(new ApplicationRole
                    {
                        Name = roleName
                    });

                    if (!result.Succeeded)
                    {
                        throw new Exception(
                            $"Failed to create role '{roleName}': {string.Join(", ", result.Errors.Select(e => e.Description))}"
                        );
                    }
                }
            }
        }
    }
}
