using System;
using System.Data;
using System.Data.SqlClient;

namespace SafeVault.Security
{
    /// <summary>
    /// Database manager using parameterized queries to prevent SQL injection
    /// </summary>
    public class DatabaseManager
    {
        private readonly string _connectionString;

        public DatabaseManager(string connectionString)
        {
            _connectionString = connectionString;
        }

        // Secure user creation with parameterized query
        public bool CreateUser(string username, string email, string passwordHash, string role = "user")
        {
            // Parameterized query prevents SQL injection
            string query = @"INSERT INTO Users (Username, Email, PasswordHash, Role)
                            VALUES (@Username, @Email, @PasswordHash, @Role)";

            using (SqlConnection connection = new SqlConnection(_connectionString))
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                // Parameters prevent SQL injection attacks
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@Email", email);
                command.Parameters.AddWithValue("@PasswordHash", passwordHash);
                command.Parameters.AddWithValue("@Role", role);

                try
                {
                    connection.Open();
                    int result = command.ExecuteNonQuery();
                    return result > 0;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error creating user: {ex.Message}");
                    return false;
                }
            }
        }

        // Secure user retrieval by username with parameterized query
        public DataRow GetUserByUsername(string username)
        {
            // Parameterized query prevents SQL injection
            string query = "SELECT * FROM Users WHERE Username = @Username";

            using (SqlConnection connection = new SqlConnection(_connectionString))
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                // Parameter prevents SQL injection
                command.Parameters.AddWithValue("@Username", username);

                try
                {
                    connection.Open();
                    using (SqlDataAdapter adapter = new SqlDataAdapter(command))
                    {
                        DataTable dt = new DataTable();
                        adapter.Fill(dt);
                        return dt.Rows.Count > 0 ? dt.Rows[0] : null;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error retrieving user: {ex.Message}");
                    return null;
                }
            }
        }

        // Secure user search with parameterized query
        public DataTable SearchUsers(string searchTerm)
        {
            // Parameterized query with LIKE prevents SQL injection
            string query = @"SELECT UserID, Username, Email, Role
                            FROM Users
                            WHERE Username LIKE @SearchTerm OR Email LIKE @SearchTerm";

            using (SqlConnection connection = new SqlConnection(_connectionString))
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                // Parameter with wildcards for LIKE query
                command.Parameters.AddWithValue("@SearchTerm", "%" + searchTerm + "%");

                try
                {
                    connection.Open();
                    using (SqlDataAdapter adapter = new SqlDataAdapter(command))
                    {
                        DataTable dt = new DataTable();
                        adapter.Fill(dt);
                        return dt;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error searching users: {ex.Message}");
                    return new DataTable();
                }
            }
        }
    }
}
