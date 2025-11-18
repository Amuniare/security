using NUnit.Framework;
using SafeVault.Security;
using System;

namespace SafeVault.Tests
{
    /// <summary>
    /// Security tests for SQL injection, XSS, authentication, and authorization
    /// </summary>
    [TestFixture]
    public class SecurityTests
    {
        // SQL INJECTION TESTS

        [Test]
        public void TestForSQLInjection_DetectsORStatement()
        {
            // Arrange: SQL injection attempt with OR statement
            string maliciousInput = "admin' OR '1'='1";

            // Act
            bool containsInjection = InputValidator.ContainsSQLInjection(maliciousInput);

            // Assert
            Assert.IsTrue(containsInjection, "Should detect SQL injection with OR statement");
        }

        [Test]
        public void TestForSQLInjection_DetectsDropTable()
        {
            // Arrange: SQL injection attempt to drop table
            string maliciousInput = "user'; DROP TABLE Users; --";

            // Act
            bool containsInjection = InputValidator.ContainsSQLInjection(maliciousInput);

            // Assert
            Assert.IsTrue(containsInjection, "Should detect DROP TABLE injection");
        }

        [Test]
        public void TestForSQLInjection_DetectsUnion()
        {
            // Arrange: UNION-based SQL injection
            string maliciousInput = "1' UNION SELECT * FROM Users --";

            // Act
            bool containsInjection = InputValidator.ContainsSQLInjection(maliciousInput);

            // Assert
            Assert.IsTrue(containsInjection, "Should detect UNION injection");
        }

        [Test]
        public void TestForSQLInjection_AllowsValidInput()
        {
            // Arrange: Valid username
            string validInput = "john_doe123";

            // Act
            bool containsInjection = InputValidator.ContainsSQLInjection(validInput);

            // Assert
            Assert.IsFalse(containsInjection, "Should allow valid input");
        }

        // XSS TESTS

        [Test]
        public void TestForXSS_DetectsScriptTag()
        {
            // Arrange: XSS attempt with script tag
            string maliciousInput = "<script>alert('XSS')</script>";

            // Act
            string sanitized = InputValidator.SanitizeInput(maliciousInput);

            // Assert
            Assert.IsFalse(sanitized.Contains("<script>"), "Should remove script tags");
        }

        [Test]
        public void TestForXSS_DetectsJavaScriptProtocol()
        {
            // Arrange: XSS with javascript: protocol
            string maliciousInput = "javascript:alert('XSS')";

            // Act
            string sanitized = InputValidator.SanitizeInput(maliciousInput);

            // Assert
            Assert.IsFalse(sanitized.ToLower().Contains("javascript:"), "Should remove javascript: protocol");
        }

        [Test]
        public void TestForXSS_DetectsEventHandler()
        {
            // Arrange: XSS with event handler
            string maliciousInput = "<img src=x onerror=alert('XSS')>";

            // Act
            string sanitized = InputValidator.SanitizeInput(maliciousInput);

            // Assert
            Assert.IsFalse(sanitized.Contains("onerror="), "Should remove event handlers");
        }

        // INPUT VALIDATION TESTS

        [Test]
        public void TestInputValidation_ValidUsername()
        {
            // Arrange
            string validUsername = "john_doe123";

            // Act
            bool isValid = InputValidator.ValidateUsername(validUsername);

            // Assert
            Assert.IsTrue(isValid, "Should accept valid username");
        }

        [Test]
        public void TestInputValidation_InvalidUsername()
        {
            // Arrange: Username with special characters
            string invalidUsername = "john<script>";

            // Act
            bool isValid = InputValidator.ValidateUsername(invalidUsername);

            // Assert
            Assert.IsFalse(isValid, "Should reject username with special characters");
        }

        [Test]
        public void TestInputValidation_ValidEmail()
        {
            // Arrange
            string validEmail = "test@safevault.com";

            // Act
            bool isValid = InputValidator.ValidateEmail(validEmail);

            // Assert
            Assert.IsTrue(isValid, "Should accept valid email");
        }

        // AUTHENTICATION TESTS

        [Test]
        public void TestAuthentication_PasswordHashing()
        {
            // Arrange
            var authManager = new AuthenticationManager(null);
            string password = "SecurePassword123!";

            // Act
            string hash = authManager.HashPassword(password);

            // Assert
            Assert.IsNotNull(hash, "Should generate password hash");
            Assert.AreNotEqual(password, hash, "Hash should not equal plain password");
            Assert.IsTrue(hash.StartsWith("$2"), "Should use bcrypt format");
        }

        [Test]
        public void TestAuthentication_PasswordVerification()
        {
            // Arrange
            var authManager = new AuthenticationManager(null);
            string password = "SecurePassword123!";
            string hash = authManager.HashPassword(password);

            // Act
            bool isValid = authManager.VerifyPassword(password, hash);
            bool isInvalid = authManager.VerifyPassword("WrongPassword", hash);

            // Assert
            Assert.IsTrue(isValid, "Should verify correct password");
            Assert.IsFalse(isInvalid, "Should reject incorrect password");
        }

        // AUTHORIZATION TESTS

        [Test]
        public void TestAuthorization_AdminHasAllPermissions()
        {
            // Arrange
            var authzManager = new AuthorizationManager();

            // Act & Assert
            Assert.IsTrue(authzManager.HasPermission("admin", "access_admin_dashboard"));
            Assert.IsTrue(authzManager.HasPermission("admin", "create_users"));
            Assert.IsTrue(authzManager.HasPermission("admin", "delete_users"));
        }

        [Test]
        public void TestAuthorization_UserHasLimitedPermissions()
        {
            // Arrange
            var authzManager = new AuthorizationManager();

            // Act & Assert
            Assert.IsTrue(authzManager.HasPermission("user", "view_profile"));
            Assert.IsFalse(authzManager.HasPermission("user", "access_admin_dashboard"));
            Assert.IsFalse(authzManager.HasPermission("user", "delete_users"));
        }

        [Test]
        public void TestAuthorization_AdminDashboardAccess()
        {
            // Arrange
            var authzManager = new AuthorizationManager();

            // Act
            bool adminCanAccess = authzManager.CanAccessAdminDashboard("admin");
            bool userCanAccess = authzManager.CanAccessAdminDashboard("user");

            // Assert
            Assert.IsTrue(adminCanAccess, "Admin should access dashboard");
            Assert.IsFalse(userCanAccess, "User should not access dashboard");
        }
    }
}
