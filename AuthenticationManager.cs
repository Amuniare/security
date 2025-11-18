using System;
using BCrypt.Net;

namespace SafeVault.Security
{
    /// <summary>
    /// Authentication manager using bcrypt for secure password hashing
    /// </summary>
    public class AuthenticationManager
    {
        private readonly DatabaseManager _dbManager;

        public AuthenticationManager(DatabaseManager dbManager)
        {
            _dbManager = dbManager;
        }

        // Hash password using bcrypt (industry standard)
        public string HashPassword(string password)
        {
            // BCrypt with work factor of 12 (2^12 iterations)
            // This makes brute force attacks computationally expensive
            return BCrypt.Net.BCrypt.HashPassword(password, 12);
        }

        // Verify password against stored hash
        public bool VerifyPassword(string password, string hash)
        {
            try
            {
                return BCrypt.Net.BCrypt.Verify(password, hash);
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Register a new user with hashed password
        public bool RegisterUser(string username, string email, string password, string role = "user")
        {
            // Validate inputs
            if (!InputValidator.ValidateUsername(username))
            {
                throw new ArgumentException("Invalid username format");
            }

            if (!InputValidator.ValidateEmail(email))
            {
                throw new ArgumentException("Invalid email format");
            }

            if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            {
                throw new ArgumentException("Password must be at least 8 characters");
            }

            // Check for SQL injection attempts
            if (InputValidator.ContainsSQLInjection(username) || InputValidator.ContainsSQLInjection(email))
            {
                throw new SecurityException("Potential SQL injection detected");
            }

            // Hash the password
            string passwordHash = HashPassword(password);

            // Create user in database
            return _dbManager.CreateUser(username, email, passwordHash, role);
        }

        // Authenticate user login
        public UserAuthResult AuthenticateUser(string username, string password)
        {
            // Validate inputs
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return new UserAuthResult { IsAuthenticated = false, Message = "Invalid credentials" };
            }

            // Check for SQL injection attempts
            if (InputValidator.ContainsSQLInjection(username))
            {
                return new UserAuthResult { IsAuthenticated = false, Message = "Invalid input detected" };
            }

            // Retrieve user from database
            var userRow = _dbManager.GetUserByUsername(username);
            if (userRow == null)
            {
                return new UserAuthResult { IsAuthenticated = false, Message = "User not found" };
            }

            // Verify password
            string storedHash = userRow["PasswordHash"].ToString();
            bool isValid = VerifyPassword(password, storedHash);

            if (isValid)
            {
                return new UserAuthResult
                {
                    IsAuthenticated = true,
                    Username = userRow["Username"].ToString(),
                    Role = userRow["Role"].ToString(),
                    Message = "Authentication successful"
                };
            }

            return new UserAuthResult { IsAuthenticated = false, Message = "Invalid credentials" };
        }
    }

    // Result object for authentication
    public class UserAuthResult
    {
        public bool IsAuthenticated { get; set; }
        public string Username { get; set; }
        public string Role { get; set; }
        public string Message { get; set; }
    }

    public class SecurityException : Exception
    {
        public SecurityException(string message) : base(message) { }
    }
}
