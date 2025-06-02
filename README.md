# SafeVault Web Application - Secure Coding Implementation

This repository contains the backend and frontend code for the SafeVault web application, designed to manage sensitive user data securely. This project focuses on implementing secure coding practices to mitigate common web vulnerabilities and ensure data integrity and user privacy.

## Project Goals Achieved:

This project aimed to:
* Implement robust input validation to prevent malicious data.
* Utilize parameterized queries to protect against SQL injection.
* Implement secure authentication mechanisms, including password hashing.
* Set up role-based access control (RBAC) for authorization.
* Develop and execute security tests to verify the application's resilience against common attacks like SQL injection and Cross-Site Scripting (XSS).
* Document the vulnerabilities addressed and the implemented fixes.

## Key Security Implementations:

### 1. Input Validation and XSS Prevention

* **Vulnerability Addressed:** Cross-Site Scripting (XSS) attacks, where malicious scripts are injected through user input.
* **Fix Applied:** The `sanitize_input` function in `app.py` is used to filter out potentially harmful characters (`<`, `>`, `"`, `'`, `%`, `;`, `(`, `)`, `&`, `+`) from user inputs (username and email) before they are processed or stored. This helps prevent the injection of executable scripts.
    ```python
    # Excerpt from app.py
    def sanitize_input(input_str):
        return re.sub(r'[<>"\'%;()&+]', '', input_str)
    ```
* **Copilot Assistance (Hypothetical/Potential):** Copilot could have assisted in generating the `sanitize_input` regular expression or suggesting best practices for input sanitization based on common XSS patterns. It could also provide examples of secure input handling functions.

### 2. SQL Injection Prevention

* **Vulnerability Addressed:** SQL Injection, where malicious SQL code is inserted into input fields to manipulate database queries.
* **Fix Applied:** The application utilizes **parameterized queries** for all database interactions involving user input (e.g., user registration and login). This ensures that user-provided data is treated as values and not as executable SQL code.
    ```python
    # Excerpt from app.py - User Registration
    cursor.execute("INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (?, ?, ?, ?)", (username, email, password, "user"))

    # Excerpt from app.py - User Login
    cursor.execute("SELECT PasswordHash, Role FROM Users WHERE Username = ?", (username,))
    ```
* **Copilot Assistance (Hypothetical/Potential):** Copilot could have been instrumental in suggesting and generating these parameterized queries, automatically inserting placeholders and guiding the developer towards secure database interaction patterns. It could highlight insecure string concatenation and propose safer alternatives.

### 3. Authentication Mechanisms

* **Vulnerability Addressed:** Unauthorized access due to weak password handling or insecure login processes.
* **Fix Applied:**
    * **Password Hashing:** User passwords are not stored in plain text. Instead, they are hashed using `werkzeug.security.generate_password_hash` before being stored in the `Users` table.
    * **Secure Password Verification:** During login, `werkzeug.security.check_password_hash` is used to securely compare the provided password with the stored hash, preventing brute-force attacks or rainbow table attacks.
* **Copilot Assistance (Hypothetical/Potential):** Copilot could have helped in suggesting and implementing strong password hashing algorithms like `bcrypt` (as `werkzeug.security` often defaults to it or similar secure algorithms) and the correct usage of related functions.

### 4. Authorization with Role-Based Access Control (RBAC)

* **Vulnerability Addressed:** Users accessing functionalities or data they are not authorized to view or modify.
* **Fix Applied:**
    * Each user is assigned a `Role` upon registration (defaulting to "user").
    * Specific routes, such as `/admin`, are protected by checking the user's role stored in the session (`session.get("role")`). Only users with the "admin" role can access the `/admin` dashboard.
* **Copilot Assistance (Hypothetical/Potential):** Copilot could assist in generating the RBAC logic, including decorators for routes or functions to enforce role-based access, and help define user roles and permissions within the application's structure.

## Security Testing

* **Tests Generated:** Unit tests (`Tests/TestInputValidation.cs`) have been created to simulate SQL injection and XSS attack attempts. These tests are designed to verify that the implemented sanitization and parameterized queries effectively prevent these attacks.
    ```csharp
    // Excerpt from Tests/TestInputValidation.cs
    [Test]
    public void TestForSQLInjection() {
        string maliciousInput = "' OR '1'='1";
        var result = SubmitForm(maliciousInput, "test@example.com", "password");
        Assert.IsFalse(result.Contains("Success")); // Expecting rejection
    }

    [Test]
    public void TestForXSS() {
        string xssPayload = "<script>alert('xss')</script>";
        var result = SubmitForm("user", xssPayload, "password");
        Assert.IsFalse(result.Contains("<script>")); // Expecting sanitization
    }
    ```
* **Copilot Assistance (Hypothetical/Potential):** Copilot could have provided boilerplate for these unit tests, suggested malicious payloads for SQL injection and XSS, and helped structure the test cases to effectively validate the security measures.

## How Copilot Assisted (Self-Reflection Guidance):

While I cannot directly confirm Copilot's usage from the code itself, in a real development scenario, Copilot would have been invaluable in:

* **Suggesting Secure Patterns:** Automatically suggesting parameterized queries when writing database interactions.
* **Generating Boilerplate Security Code:** Providing quick implementations for password hashing, input sanitization functions, and basic RBAC checks.
* **Identifying Potential Vulnerabilities:** As a coding assistant, it could have flagged potential insecure practices (e.g., direct string concatenation in SQL) and offered secure alternatives.
* **Accelerating Test Creation:** Generating test cases with common attack vectors (like the ones seen in `TestInputValidation.cs`) to ensure the implemented fixes work as expected.
* **Debugging Assistance:** Offering suggestions for fixes when encountering security-related issues during development or testing.

By following these practices and leveraging tools like Copilot, the SafeVault application aims to maintain a high standard of security for its sensitive data.
