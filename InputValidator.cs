using System;
using System.Text.RegularExpressions;
using System.Web;

namespace SafeVault.Security
{
    /// <summary>
    /// Input validation and sanitization to prevent XSS and injection attacks
    /// </summary>
    public static class InputValidator
    {
        // Validates username: 3-20 alphanumeric characters and underscores only
        public static bool ValidateUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            var usernamePattern = @"^[a-zA-Z0-9_]{3,20}$";
            return Regex.IsMatch(username, usernamePattern);
        }

        // Validates email format
        public static bool ValidateEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            var emailPattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
            return Regex.IsMatch(email, emailPattern);
        }

        // Sanitizes input to prevent XSS attacks
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // HTML encode to prevent XSS
            string sanitized = HttpUtility.HtmlEncode(input);

            // Remove potentially dangerous patterns
            sanitized = Regex.Replace(sanitized, @"<script.*?>.*?</script>", "", RegexOptions.IgnoreCase);
            sanitized = Regex.Replace(sanitized, @"javascript:", "", RegexOptions.IgnoreCase);
            sanitized = Regex.Replace(sanitized, @"on\w+\s*=", "", RegexOptions.IgnoreCase);

            return sanitized;
        }

        // Detects potential SQL injection patterns
        public static bool ContainsSQLInjection(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            var sqlPatterns = new[]
            {
                @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
                @"(-{2}|/\*|\*/)",  // SQL comments
                @"('\s*(OR|AND)\s*'?\d)",  // OR 1=1, AND 1=1
                @"(;\s*(SELECT|INSERT|UPDATE|DELETE))"  // Command chaining
            };

            foreach (var pattern in sqlPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                    return true;
            }

            return false;
        }
    }
}
