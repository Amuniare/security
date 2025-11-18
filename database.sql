-- SafeVault Database Schema

-- Users table with role-based access control
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(255) NOT NULL,
    Role VARCHAR(20) DEFAULT 'user',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster lookups
CREATE INDEX idx_username ON Users(Username);
CREATE INDEX idx_email ON Users(Email);

-- Sample data with hashed passwords
-- Note: In production, passwords should be hashed using bcrypt/Argon2
INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES
('admin', 'admin@safevault.com', '$2a$12$examplehash1', 'admin'),
('testuser', 'user@safevault.com', '$2a$12$examplehash2', 'user');
