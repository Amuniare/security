using System;
using System.Collections.Generic;

namespace SafeVault.Security
{
    /// <summary>
    /// Role-Based Access Control (RBAC) manager
    /// </summary>
    public class AuthorizationManager
    {
        // Define permissions for each role
        private static readonly Dictionary<string, HashSet<string>> RolePermissions = new Dictionary<string, HashSet<string>>
        {
            {
                "admin", new HashSet<string>
                {
                    "view_users",
                    "create_users",
                    "delete_users",
                    "modify_users",
                    "access_admin_dashboard",
                    "view_reports",
                    "manage_roles"
                }
            },
            {
                "user", new HashSet<string>
                {
                    "view_profile",
                    "edit_profile",
                    "view_data"
                }
            }
        };

        // Check if a user has a specific permission
        public bool HasPermission(string role, string permission)
        {
            if (string.IsNullOrWhiteSpace(role) || string.IsNullOrWhiteSpace(permission))
                return false;

            role = role.ToLower();

            if (!RolePermissions.ContainsKey(role))
                return false;

            return RolePermissions[role].Contains(permission);
        }

        // Check if user has admin role
        public bool IsAdmin(string role)
        {
            return role?.ToLower() == "admin";
        }

        // Authorize access to a resource
        public AuthorizationResult AuthorizeAccess(string role, string requiredPermission)
        {
            if (string.IsNullOrWhiteSpace(role))
            {
                return new AuthorizationResult
                {
                    IsAuthorized = false,
                    Message = "Invalid role"
                };
            }

            bool hasPermission = HasPermission(role, requiredPermission);

            return new AuthorizationResult
            {
                IsAuthorized = hasPermission,
                Message = hasPermission ? "Access granted" : "Access denied: insufficient permissions"
            };
        }

        // Authorize admin dashboard access
        public bool CanAccessAdminDashboard(string role)
        {
            return HasPermission(role, "access_admin_dashboard");
        }

        // Authorize user management operations
        public bool CanManageUsers(string role)
        {
            return HasPermission(role, "create_users") || HasPermission(role, "delete_users");
        }

        // Get all permissions for a role
        public HashSet<string> GetRolePermissions(string role)
        {
            if (string.IsNullOrWhiteSpace(role))
                return new HashSet<string>();

            role = role.ToLower();

            if (RolePermissions.ContainsKey(role))
                return new HashSet<string>(RolePermissions[role]);

            return new HashSet<string>();
        }
    }

    // Result object for authorization
    public class AuthorizationResult
    {
        public bool IsAuthorized { get; set; }
        public string Message { get; set; }
    }
}
