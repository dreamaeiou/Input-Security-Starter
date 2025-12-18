# Input Security Starter

[English](./README.md) | [中文](./README_ZH.md)

```
    ____                  __     _____                      _ __           _____ ____  __ __
   /  _/___  ____  __  __/ /_   / ___/___  _______  _______(_) /___  __   / ___// __ \/ //_/
   / // __ \/ __ \/ / / / __/   \__ \/ _ \/ ___/ / / / ___/ / __/ / / /   \__ \/ / / / ,<
 _/ // / / / /_/ / /_/ / /_    ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ /   ___/ / /_/ / /| |
/___/_/ /_/ .___/\__,_/\__/   /____/\___/\___/\__,_/_/  /_/\__/\__, /   /____/_____/_/ |_|
         /_/                                                  /____/
```

## Project Introduction

Input Security Starter is a Spring Boot-based security input detection starter that helps your application detect and block common web attacks such as XSS and SQL injection. This starter adopts a zero-intrusion design, providing security protection for your application with simple configuration.

Drawing inspiration from Swagger's design concept, this component provides an embedded visual management interface, allowing developers to view security rules and monitor attack events conveniently.

The starter now uses optimized regular expression matching for accurate pattern detection while maintaining high performance through pre-compilation and priority-based matching.

## Features

1. **Zero Intrusion Integration** - Automatically assembled through Spring Boot Starter mechanism without modifying existing code
2. **Multiple Security Rules** - Built-in detection rules for various common attacks such as XSS attacks and SQL injection
3. **Two Working Modes** - Supports monitoring mode (record threats only) and blocking mode (directly block threats)
4. **Visual Management Interface** - Provides an embedded web UI interface for viewing rules and monitoring events
5. **Security Event Logging** - Automatically records all detected security events to a text file
6. **Highly Configurable** - Specific rules can be enabled/disabled or rule parameters adjusted via configuration file
7. **Thymeleaf Support** - Provides a Thymeleaf-based web interface for interactive operations
8. **Optimized Pattern Matching** - Uses pre-compiled patterns with priority-based matching for high performance

## System Requirements

- Java 8 or higher
- Spring Boot 2.7.18

## Quick Start

### 1. Add Dependency

After installing the project to your local repository via Maven install, add the following dependency to your project:

```xml
<dependency>
    <groupId>org.example</groupId>
    <artifactId>input-security-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. Configuration Parameters

Add the following configuration to `application.properties`:

```properties
# Enable security detection feature (default is true)
input-security.enabled=true

# Set working mode: monitor (monitor only) or block (intercept) (default is monitor)
input-security.mode=block
```

Enable component scanning in the `application` entry class:

```java
@SpringBootApplication(scanBasePackages = {"com.yourcompany", "org.example.input_security_starter"})
```

> Note: If your project uses Spring Boot 2.x, you need to add the `@ComponentScan` annotation to the main application class:

```java
@SpringBootApplication
@ComponentScan({"com.yourcompany", "org.example.input_security_starter"})
```

### 3. Access Management Interface

After starting the application, you can access the Thymeleaf version of the interface via the following address:
```
http://your-ip:your-port/input-security-view/events
```

You can test on this page:
```
http://your-ip:your-port/input-security-view/test
```

In the management interface, you can:
- View all built-in security rules
- Test if input content triggers security rules
- View detected security events

## Security Logs

The system automatically records all detected security events to the `security-events.log` file in the application root directory. Each log record contains the following information:

- Timestamp
- Client IP address
- Attack type (triggered security rule name)
- HTTP method
- Detected malicious input content

Log format example:
```
2025-12-17T11:30:04.3107906 | 127.0.0.1 | system-command | GET | exec(1
2025-12-17T11:30:04.3580229 | 127.0.0.1 | system-command | GET | http://localhost:8080/input-security-api/test?input=exec(1
2025-12-17T11:31:22.197644 | 127.0.0.1 | sql-union-select | GET | union select
2025-12-17T11:31:47.7353782 | 127.0.0.1 | xss-script-tag | GET | <script>alert(1)</script>
```

## Configuration Options

| Configuration Item | Description | Default Value |
|--------------------|-------------|---------------|
| input-security.enabled | Whether to enable security detection feature | true |
| input-security.mode | Working mode (monitor/block) | monitor |

## Built-in Security Rules

This starter includes various common security rules, which are grouped by attack type:

1. **XSS Attack Protection** (`xss-attack`)
   - Script tag detection
   - Event handler detection (onclick, etc.)
   - JavaScript/VBScript URI detection
   - Data URI detection
   - SVG Script detection
   - IMG src JavaScript injection
   - Object/Embed tag detection
   - Expression detection
   - Meta refresh detection
   - Import statement detection
   - Base href manipulation
   - Iframe tag detection
   - Form action JavaScript injection
   - Style tag with expression
   - Link tag with JavaScript URI
   - Body onload event
   - Background image URL injection

2. **SQL Injection Protection** (`sql-injection`)
   - UNION SELECT statement detection
   - EXEC/EXECUTE statement detection
   - DROP TABLE statement detection
   - CREATE TABLE statement detection
   - INSERT INTO statement detection
   - UPDATE SET statement detection
   - DELETE FROM statement detection
   - SQL comment detection
   - Sleep function detection
   - Benchmark function detection
   - Backtick injection detection
   - Hexadecimal injection detection
   - CHAR function injection
   - NVARCHAR cast detection

3. **Code Execution Protection** (`code-execution`)
   - Eval/Timeout functions detection
   - System command functions detection
   - Reflection invoke detection
   - File operation functions detection

4. **SSRF (Server-Side Request Forgery) Protection** (`ssrf-attack`)
   - URL connection classes detection
   - Curl/Wget command detection
   - File protocol access detection

5. **Command Injection Protection** (`command-injection`)
   - Pipe and special characters detection
   - Shell command keywords detection

6. **Path Traversal Protection** (`path-traversal`)
   - Path traversal detection
   - Encoded path traversal detection

7. **LDAP Injection Protection** (`ldap-injection`)
   - LDAP injection detection

8. **XXE (XML External Entity) Injection Protection** (`xxe-injection`)
   - XML entity declaration detection
   - XML doctype declaration detection

## Custom Rules

The current version does not support customizing rules via configuration files, which will be supported in subsequent versions.

## Technical Implementation

This project is implemented based on the following technologies:

- Spring Boot auto-configuration mechanism
- Servlet Filter technology
- Optimized regular expression matching with pre-compilation and priority-based ordering
- RESTful API design
- Thymeleaf template engine

## Performance Improvements

We've optimized regular expression matching with the following techniques:

1. **Pre-compilation**: All patterns are pre-compiled during initialization for optimal runtime performance
2. **Priority-based Matching**: High threat level rules are matched first to detect critical attacks early
3. **Accurate Detection**: Full regular expression syntax support ensures accurate pattern matching

## License

This project is for learning and communication purposes only.