# Input Security Starter

## 项目简介

Input Security Starter 是一个基于 Spring Boot 的安全输入检测 starter，可以帮助你的应用程序检测和阻止常见的 Web 攻击，如 XSS 和 SQL 注入等。该 starter 采用了零侵入式设计，只需简单配置即可为你的应用提供安全保护。

该组件借鉴了 Swagger 的设计理念，提供了内嵌的可视化管理界面，方便开发者查看安全规则和监控攻击事件。

## 功能特性

1. **零侵入式集成** - 通过 Spring Boot Starter 机制自动装配，无需修改现有代码
2. **多种安全规则** - 内置 XSS 攻击、SQL 注入等多种常见攻击的检测规则
3. **两种工作模式** - 支持监控模式（只记录威胁）和拦截模式（直接阻止威胁）
4. **可视化管理界面** - 提供内嵌的 Web UI 界面，用于查看规则和监控事件
5. **高度可配置** - 可通过配置文件启用/禁用特定规则或调整规则参数

## 系统要求

- Java 17 或更高版本
- Spring Boot 3.3.0

## 快速开始

### 1. 添加依赖

在你的 Maven 项目中添加以下依赖：

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

### 3. 访问管理界面

启动应用程序后，可以通过以下地址访问内嵌的管理界面：
```
http://localhost:8080/input-security-ui
```

在管理界面中，你可以：
- 查看所有内置的安全规则
- 测试输入内容是否会触发安全规则
- 查看已检测到的安全事件

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

## 许可证

本项目仅供学习交流使用。