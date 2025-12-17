# Input Security Starter

[English](README.md) | [中文](./README_ZH.md)

```
    ____                  __     _____                      _ __           _____ ____  __ __
   /  _/___  ____  __  __/ /_   / ___/___  _______  _______(_) /___  __   / ___// __ \/ //_/
   / // __ \/ __ \/ / / / __/   \__ \/ _ \/ ___/ / / / ___/ / __/ / / /   \__ \/ / / / ,<
 _/ // / / / /_/ / /_/ / /_    ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ /   ___/ / /_/ / /| |
/___/_/ /_/ .___/\__,_/\__/   /____/\___/\___/\__,_/_/  /_/\__/\__, /   /____/_____/_/ |_|
         /_/                                                  /____/
```

## 项目简介

Input Security Starter 是一个基于 Spring Boot 的安全输入检测 starter，可以帮助你的应用程序检测和阻止常见的 Web 攻击，如 XSS 和 SQL 注入等。该 starter 采用了零侵入式设计，只需简单配置即可为你的应用提供安全保护。

该组件借鉴了 Swagger 的设计理念，提供了内嵌的可视化管理界面，方便开发者查看安全规则和监控攻击事件。

## 功能特性

1. **零侵入式集成** - 通过 Spring Boot Starter 机制自动装配，无需修改现有代码
2. **多种安全规则** - 内置 XSS 攻击、SQL 注入等多种常见攻击的检测规则
3. **两种工作模式** - 支持监控模式（只记录威胁）和拦截模式（直接阻止威胁）
4. **可视化管理界面** - 提供内嵌的 Web UI 界面，用于查看规则和监控事件
5. **安全事件日志** - 自动记录所有检测到的安全事件到文本文件
6. **高度可配置** - 可通过配置文件启用/禁用特定规则或调整规则参数
7. **Thymeleaf 支持** - 提供基于 Thymeleaf 的 Web 界面，便于交互式操作

## 系统要求

- Java 8 或更高版本
- Spring Boot 2.7.18

## 快速开始

### 1. 添加依赖

将工程经Maven install 到你的本地仓库后，在项目中添加以下依赖：

```xml
<dependency>
    <groupId>org.example</groupId>
    <artifactId>input-security-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### 2. 配置参数

在 `application.properties` 中添加以下配置：

```properties
# 启用安全检测功能（默认为 true）
input-security.enabled=true

# 设置工作模式：monitor（仅监控）或 block（拦截）（默认为 monitor）
input-security.mode=block
```

在 `application` 入口类开启组件扫描

```java
@SpringBootApplication(scanBasePackages = {"com.yourcompany", "org.example.input_security_starter"})
```

> 注意：如果你的项目使用的是Spring Boot 2.x版本，则需要在主应用类上添加`@ComponentScan`注解：

```java
@SpringBootApplication
@ComponentScan({"com.yourcompany", "org.example.input_security_starter"})
```

### 3. 访问管理界面

启动应用程序后，可以通过以下地址访问 Thymeleaf 版本的界面：
```
http://your-ip:your-port/input-security-view/events
```

可以在此页面进行测试：
```
http://your-ip:your-port/input-security-view/test
```

在管理界面中，你可以：
- 查看所有内置的安全规则
- 测试输入内容是否会触发安全规则
- 查看已检测到的安全事件

## 安全日志

系统会自动将检测到的所有安全事件记录到应用程序根目录下的 `security-events.log` 文件中。每条日志记录包含以下信息：

- 时间戳
- 客户端 IP 地址
- 攻击类型（触发的安全规则名称）
- HTTP 方法
- 检测到的恶意输入内容

日志格式示例：
```
2025-12-17T11:30:04.3107906 | 127.0.0.1 | system-command | GET | exec(1
2025-12-17T11:30:04.3580229 | 127.0.0.1 | system-command | GET | http://localhost:8080/input-security-api/test?input=exec(1
2025-12-17T11:31:22.197644 | 127.0.0.1 | sql-union-select | GET | union select
2025-12-17T11:31:47.7353782 | 127.0.0.1 | xss-script-tag | GET | <script>alert(1)</script>
```

## 配置选项

| 配置项 | 描述 | 默认值 |
|--------|------|--------|
| input-security.enabled | 是否启用安全检测功能 | true |
| input-security.mode | 工作模式（monitor/block） | monitor |

## 内置安全规则

该 starter 内置了多种常见的安全规则，包括：

1. **XSS 攻击防护**
   - Script 标签检测
   - 事件处理器检测（onclick 等）
   - JavaScript/VBScript URI 检测
   - SVG Script 检测等

2. **SQL 注入防护**
   - UNION SELECT 语句检测
   - DROP/CREATE TABLE 语句检测
   - SQL 注释检测等

3. **其他攻击防护**
   - 代码执行检测
   - 文件操作检测
   - SSRF（服务器端请求伪造）检测等

## 自定义规则

目前版本暂不支持通过配置文件自定义规则，将在后续版本中支持。

## 技术实现

该项目基于以下技术实现：

- Spring Boot 自动装配机制
- Servlet Filter 技术
- 正则表达式匹配引擎
- RESTful API 设计
- Thymeleaf 模板引擎

## 许可证

本项目仅供学习交流使用。