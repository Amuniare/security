Introduction
In this activity, you’ll use Microsoft Copilot to generate secure code for a web application, focusing on mitigating common vulnerabilities such as SQL injection and cross-site scripting (XSS). You’ll also write tests to ensure the generated code protects against potential security threats.

This is the first of three activities in which you’ll secure the SafeVault application. The secure coding practices implemented here will serve as the foundation for authentication and authorization systems in subsequent activities.

Instructions
Step 1: Review the scenario
To begin, review the following scenario related to building the "SafeVault" web application:

SafeVault is a secure web application designed to manage sensitive data, including user credentials and financial records. As the lead developer, your role is to ensure the application is robust against attacks by implementing secure coding practices.

The initial requirements include:

Validating user inputs to prevent malicious injections.

Securing database queries to eliminate SQL injection vulnerabilities.

Testing the code to ensure it resists XSS and SQL injection attacks.

Your goal is to use Microsoft Copilot to write secure code and generate tests that simulate attack scenarios.

Here is the base code for the application:

Web Form (Input Validation)

12345678910
<!-- webform.html -->
<form action="/submit" method="post">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username">
    
    <label for="email">Email:</label>
    <input type="email" id="email" name="email">
    
    <button type="submit">Submit</button>
</form>
Database Schema and Connection (Parameterized Queries)

123456
-- database.sql
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100),
    Email VARCHAR(100)
);
Test Framework Setup (Testing for Vulnerabilities)

678910111213
// Tests/TestInputValidation.cs
using NUnit.Framework;
[TestFixture]
public class TestInputValidation {
    [Test]
    public void TestForSQLInjection() {
        // Placeholder for SQL Injection test
    }
    [Test]
    public void TestForXSS() {

Step 2: Generate secure code for input validation
Use Copilot to generate code that:

Validates user inputs by removing malicious characters and ensuring data integrity.

Prevents users from entering potentially harmful scripts or queries.

Example: Implement a function that sanitizes inputs in a web form, such as username and email.

Step 3: Use parameterized queries to prevent SQL injection
Use Copilot to:

Write database queries using parameterized statements.

Securely handle user-provided data, such as login credentials or search inputs.

Example: Generate a secure query to retrieve user information by using placeholders for parameters.

Step 4: Test the code for vulnerabilities
Use Copilot to:

Generate unit tests to simulate SQL injection attempts.

Write tests for XSS vulnerabilities by injecting malicious scripts into user inputs.

Run the tests and verify that the generated code effectively prevents these attacks.

Step 5: Save your work
By the end of this activity, you will have:

Secure code that validates user inputs and prevents SQL injection attacks.

Tests that verify the robustness of the code against common vulnerabilities.

Save all secure code and test cases in your sandbox environment. This work will be expanded in Activity 2, where you’ll implement authentication and authorization systems.


In this activity, you’ll secure the SafeVault application by implementing authentication and authorization mechanisms. Authentication ensures that only legitimate users can access the system, while authorization restricts access to specific features based on user roles. Using Microsoft Copilot, you’ll generate and test code to establish these essential security layers. 

This is the second of three activities. The secure coding practices and base code implemented in Activity 1 will serve as the foundation for protecting user accounts in this activity.

Instructions
Step 1: Review the scenario
SafeVault needs robust access control mechanisms to prevent unauthorized access to sensitive data. The system should:

Verify user credentials during login (authentication).

Restrict access to certain features, such as administrative tools, based on user roles (authorization).

Your goal is to use Microsoft Copilot to generate code for these functionalities and test them for reliability.

Step 2: Generate authentication code
Use Copilot to:

Write code for user login functionality, including verifying usernames and passwords.

Hash passwords securely using a library like bcrypt or Argon2.

Example: Implement a function to authenticate users by comparing hashed passwords.

Step 3: Implement role-based authorization (RBAC)
Use Copilot to generate code that:

Assigns roles to users (e.g., admin, user).

Restricts access to specific routes or features based on roles.

Example: Protect the Admin Dashboard so only users with the admin role can access it.

Step 4: Test the authentication and authorization system
Use Copilot to:

Write test cases to simulate scenarios like invalid login attempts and unauthorized access.

Test access control for users with different roles.

Step 5: Save your work
By the end of this activity, you will have:

A working authentication and authorization system for SafeVault.

Tests verifying proper access control for different user roles.

Save the authentication and authorization code and test cases in your sandbox environment. These systems will be further debugged and secured in Activity 3.


Introduction
Even with secure coding practices, vulnerabilities can still exist. In this activity, you’ll use Microsoft Copilot to debug and resolve security vulnerabilities in the SafeVault application. This includes identifying issues like SQL injection risks and XSS vulnerabilities, applying fixes, and testing the corrected code to ensure it’s secure.

This is the final activity in the project, ensuring the SafeVault application is secure and ready for deployment.

Instructions
Step 1: Review the scenario
You’ve implemented secure coding practices and access control mechanisms in SafeVault, but further testing has revealed potential vulnerabilities. These include:

SQL injection risks in database queries.

Cross-site scripting (XSS) risks in handling user-generated content.

Your goal is to debug these issues using Microsoft Copilot and apply fixes to secure the application.

Step 2: Identify vulnerabilities in the codebase
Use Copilot to:

Analyze the codebase and identify insecure queries or output handling.

Detect specific vulnerabilities such as:

Unsafe string concatenation in SQL queries.

Lack of input sanitization in form handling.

Step 3: Fix security issues with Copilot
Use Copilot’s suggestions to:

Replace insecure queries with parameterized statements.

Sanitize and escape user inputs to prevent XSS attacks.

Step 4: Test the fixed code
Use Copilot to:

Generate tests that simulate attack scenarios, such as:

SQL injection attempts with malicious input.

XSS attacks through form fields.

Verify that the fixed code effectively blocks these attacks.

Step 5: Save and summarize your work
By the end of this activity, you will have:

Debugged and secured the SafeVault codebase against common vulnerabilities.

Tests confirming the application’s robustness against attacks.

Save the debugged and secured codebase in your sandbox environment. Prepare a summary of the vulnerabilities identified, the fixes applied, and how Copilot assisted in the debugging process.


 To complete this assignment, you will submit the secure code and tests you’ve been working on in previous activities. In earlier activities, you:

Generated secure code for input validation and SQL injection prevention.

Implemented authentication and authorization mechanisms to control user access.

Debugged and resolved security vulnerabilities in the SafeVault application.

This project combines all these activities into a comprehensive submission for review and feedback.

There are a total of 30 points for this project:

(5 pts) Did you create a GitHub repository for your project?

(5 pts) Did you use Copilot to generate secure code for input validation and SQL injection prevention?

(5 pts) Did you use Copilot to implement authentication and authorization mechanisms, including role-based access control (RBAC)??

(5 pts) Did you debug and resolve security vulnerabilities such as SQL injection and XSS?

(5 pts) Did you generate and execute tests to verify the application’s security?

(5pts) Did you include a brief summary of the vulnerabilities identified, the fixes applied, and how Copilot assisted in the debugging process?
