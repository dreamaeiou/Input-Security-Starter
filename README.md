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

## Features

1. **Zero Intrusion Integration** - Automatically assembled through Spring Boot Starter mechanism without modifying existing code
2. **Multiple Security Rules** - Built-in detection rules for various common attacks such as XSS attacks and SQL injection
3. **Two Working Modes** - Supports monitoring mode (record threats only) and blocking mode (directly block threats)
4. **Visual Management Interface** - Provides an embedded web UI interface for viewing rules and monitoring events
5. **Security Event Logging** - Automatically records all detected security events to a text file
6. **Highly Configurable** - Specific rules can be enabled/disabled or rule parameters adjusted via configuration file
7. **Thymeleaf Support** - Provides a Thymeleaf-based web interface for interactive operations

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
    <version>0.0.1-SNAPSHOT</version>
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

This starter includes various common security rules, including:

1. **XSS Attack Protection**
   - Script tag detection (`xss-script-tag`)
   - Event handler detection (onclick, etc.) (`xss-on-event`)
   - JavaScript/VBScript URI detection (`xss-javascript-uri`, `xss-vbscript-uri`)
   - Data URI detection (`xss-data-uri`)
   - SVG Script detection (`xss-svg-script`)
   - IMG src JavaScript injection (`xss-img-src-xss`)
   - Object/Embed tag detection (`xss-object-tag`, `xss-embed-tag`)
   - Expression detection (`xss-expression`)
   - Meta refresh detection (`xss-meta-refresh`)
   - Import statement detection (`xss-import-statement`)
   - Base href manipulation (`xss-base-href`)
   - Iframe tag detection (`xss-iframe-tag`)
   - Form action JavaScript injection (`xss-form-action`)
   - Style tag with expression (`xss-style-tag`)
   - Link tag with JavaScript URI (`xss-link-tag`)
   - Body onload event (`xss-body-tag`)
   - Background image URL injection (`xss-background-prop`)

2. **SQL Injection Protection**
   - UNION SELECT statement detection (`sql-union-select`)
   - EXEC/EXECUTE statement detection (`sql-exec`)
   - DROP TABLE statement detection (`sql-drop-table`)
   - CREATE TABLE statement detection (`sql-create-table`)
   - INSERT INTO statement detection (`sql-insert-into`)
   - UPDATE SET statement detection (`sql-update-set`)
   - DELETE FROM statement detection (`sql-delete-from`)
   - SQL comment detection (`sql-comment`)
   - Sleep function detection (`sql-sleep`)
   - Benchmark function detection (`sql-benchmark`)
   - Backtick injection detection (`sql-backtick-injection`)
   - Hexadecimal injection detection (`sql-hex-injection`)
   - CHAR function injection (`sql-char-injection`)
   - NVARCHAR cast detection (`sql-nvarchar-cast`)

3. **Code Execution Protection**
   - Eval/Timeout functions detection (`eval-js`)
   - System command functions detection (`system-command`)
   - Reflection invoke detection (`reflection-invoke`)

4. **File Operation Protection**
   - File operation functions detection (`file-operation`)

5. **SSRF (Server-Side Request Forgery) Protection**
   - URL connection classes detection (`ssrf-url-connection`)
   - Curl/Wget command detection (`ssrf-curl`)
   - File protocol access detection (`ssrf-file-protocol`)

6. **Command Injection Protection**
   - Pipe and special characters detection (`command-injection-pipe`)
   - Shell command keywords detection (`command-injection-shell-keywords`)

7. **Path Traversal Protection**
   - Path traversal detection (`path-traversal`)
   - Encoded path traversal detection (`path-traversal-encoded`)

8. **LDAP Injection Protection**
   - LDAP injection detection (`ldap-injection`)

9. **XXE (XML External Entity) Injection Protection**
   - XML entity declaration detection (`xxe-entity`)
   - XML doctype declaration detection (`xxe-doctype`)

## Custom Rules

The current version does not support customizing rules via configuration files, which will be supported in subsequent versions.

## Technical Implementation

This project is implemented based on the following technologies:

- Spring Boot auto-configuration mechanism
- Servlet Filter technology
- Regular expression matching engine
- RESTful API design
- Thymeleaf template engine

## License

This project is for learning and communication purposes only.