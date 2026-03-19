package org.example.input_security_starter.filter;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.Collections;
import java.util.List;

/**
 * 输入安全过滤器
 * 对HTTP请求进行全面的安全检测，包括：
 * 1. URL参数检测
 * 2. 请求头检测
 * 3. Cookie检测
 * 4. 请求体检测（JSON/XML等）
 * 
 * 支持两种工作模式：
 * - MONITOR：仅记录威胁，不阻止请求
 * - BLOCK：检测到威胁时直接返回403错误
 */
public class InputSecurityFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(InputSecurityFilter.class);

    private static final int DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024;

    private final InputSecurityProperties properties;
    private final OptimizedRuleEngine ruleEngine;
    private final EventRecorder eventRecorder;
    private final int maxBodySize;
    private final List<String> trustedProxies;
    private final DetailedViolationHandler detailedViolationHandler;

    /**
     * 构造函数
     * @param properties 安全配置属性
     * @param ruleEngine 规则引擎
     * @param eventRecorder 事件记录器
     */
    public InputSecurityFilter(InputSecurityProperties properties, OptimizedRuleEngine ruleEngine, EventRecorder eventRecorder) {
        this.properties = properties;
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
        this.maxBodySize = DEFAULT_MAX_BODY_SIZE;
        this.trustedProxies = Collections.emptyList();
        this.detailedViolationHandler = new DetailedViolationHandler(ruleEngine, eventRecorder);
    }

    /**
     * 带信任代理配置的构造函数
     * @param properties 安全配置属性
     * @param ruleEngine 规则引擎
     * @param eventRecorder 事件记录器
     * @param trustedProxies 可信任的代理 IP 列表
     */
    public InputSecurityFilter(InputSecurityProperties properties, OptimizedRuleEngine ruleEngine, EventRecorder eventRecorder, List<String> trustedProxies) {
        this.properties = properties;
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
        this.maxBodySize = DEFAULT_MAX_BODY_SIZE;
        this.trustedProxies = trustedProxies != null ? trustedProxies : Collections.emptyList();
        this.detailedViolationHandler = new DetailedViolationHandler(ruleEngine, eventRecorder);
        log.info("InputSecurityFilter initialized - excludePaths: {}", properties.getExcludePaths());
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.info("InputSecurityFilter init - excludePaths: {}", properties.getExcludePaths());
    }

    /**
     * 过滤器核心方法，对请求进行安全检测
     * @param request 请求对象
     * @param response 响应对象
     * @param chain 过滤器链
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!properties.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String url = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();
        
        String clientIp = getClientIp(httpRequest);

        if (shouldExclude(url)) {
            log.debug("URL excluded from security check: {}", url);
            chain.doFilter(request, response);
            return;
        }

        String rule = checkParameters(httpRequest);
        if (rule != null) {
            boolean blocked = handleViolation(rule, "parameter", url, method, clientIp, (HttpServletResponse) response);
            if (blocked) {
                return;
            }
        }

        rule = checkHeaders(httpRequest);
        if (rule != null) {
            boolean blocked = handleViolation(rule, "header", url, method, clientIp, (HttpServletResponse) response);
            if (blocked) {
                return;
            }
        }

        rule = checkCookies(httpRequest);
        if (rule != null) {
            boolean blocked = handleViolation(rule, "cookie", url, method, clientIp, (HttpServletResponse) response);
            if (blocked) {
                return;
            }
        }

        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(httpRequest, maxBodySize);
        rule = checkRequestBody(cachedRequest);
        if (rule != null) {
            boolean blocked = handleViolation(rule, "body", url, method, clientIp, (HttpServletResponse) response);
            if (blocked) {
                return;
            }
        }

        chain.doFilter(cachedRequest, response);
    }
    
    /**
     * 检查 URL 是否应该被排除
     * 支持精确匹配、前缀匹配和 Ant 风格路径匹配
     */
    private boolean shouldExclude(String url) {
        if (url.startsWith("/input-security-ui") || 
            url.startsWith("/input-security-view") || 
            url.startsWith("/input-security-api")) {
            return true;
        }
        
        List<String> excludePaths = properties.getExcludePaths();
        if (log.isDebugEnabled()) {
            log.debug("shouldExclude check for URL: {}, excludePaths: {}", url, excludePaths);
        }
        
        if (excludePaths != null && !excludePaths.isEmpty()) {
            for (String excludePath : excludePaths) {
                if (excludePath == null || excludePath.isEmpty()) {
                    continue;
                }
                // 精确匹配
                if (url.equals(excludePath)) {
                    return true;
                }
                // 扩展名匹配 (/**.js, /**.css 等)
                if (excludePath.startsWith("/**.")) {
                    String ext = excludePath.substring(3);
                    if (url.endsWith(ext)) {
                        return true;
                    }
                }
                // 前缀匹配（处理 /static/** 或 /static/ 的情况）
                if (excludePath.endsWith("/**")) {
                    String prefix = excludePath.substring(0, excludePath.length() - 3);
                    if (url.startsWith(prefix)) {
                        return true;
                    }
                } else if (excludePath.endsWith("/*")) {
                    String prefix = excludePath.substring(0, excludePath.length() - 2);
                    if (url.startsWith(prefix)) {
                        return true;
                    }
                } else if (url.startsWith(excludePath)) {
                    // 普通前缀匹配
                    return true;
                }
            }
        }
        
        List<String> includePaths = properties.getIncludePaths();
        if (includePaths != null && !includePaths.isEmpty()) {
            for (String includePath : includePaths) {
                if (includePath == null || includePath.isEmpty()) {
                    continue;
                }
                // 精确匹配
                if (url.equals(includePath)) {
                    return false;
                }
                // 扩展名匹配 (/**.js, /**.css 等)
                if (includePath.startsWith("/**.")) {
                    String ext = includePath.substring(3);
                    if (url.endsWith(ext)) {
                        return false;
                    }
                }
                // 前缀匹配（处理 /api/** 或 /api/ 的情况）
                if (includePath.endsWith("/**")) {
                    String prefix = includePath.substring(0, includePath.length() - 3);
                    if (url.startsWith(prefix)) {
                        return false;
                    }
                } else if (includePath.endsWith("/*")) {
                    String prefix = includePath.substring(0, includePath.length() - 2);
                    if (url.startsWith(prefix)) {
                        return false;
                    }
                } else if (url.startsWith(includePath)) {
                    // 普通前缀匹配
                    return false;
                }
            }
            // 如果设置了 include-paths 但都不匹配，则排除
            return true;
        }
        
        return false;
    }

    /**
     * 检查 URL 参数中的恶意输入
     * @param request HTTP 请求对象
     * @return 匹配到的规则名，未匹配到则返回 null
     */
    private String checkParameters(HttpServletRequest request) {
        // 安全获取参数 Map，防止空指针
        java.util.Map<String, String[]> parameterMap = request.getParameterMap();
        if (parameterMap == null || parameterMap.isEmpty()) {
            return null;
        }
        
        for (String paramName : parameterMap.keySet()) {
            String[] values = parameterMap.get(paramName);
            // 安全检查参数值数组
            if (values == null) {
                continue;
            }
            for (String value : values) {
                if (value == null) {
                    continue;
                }
                String rule = ruleEngine.match(value);
                if (rule != null) {
                    String clientIp = getClientIp(request);
                    // 记录详细日志（用于 LLM 分析）
                    try {
                        detailedViolationHandler.handleViolation(
                            value,
                            value,
                            rule,
                            "parameter",
                            paramName,
                            clientIp,
                            request
                        );
                    } catch (Exception e) {
                        log.error("Failed to record detailed violation", e);
                    }
                    return rule;
                }
            }
        }
        return null;
    }

    /**
     * 检查请求头中的恶意输入
     * @param request HTTP 请求对象
     * @return 匹配到的规则名，未匹配到则返回 null
     */
    private String checkHeaders(HttpServletRequest request) {
        // 安全获取 Header 名称枚举，防止空指针
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames == null) {
            return null;
        }
        
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            if (name == null) {
                continue;
            }
            String value = request.getHeader(name);
            if (value == null) {
                continue;
            }
            String rule = ruleEngine.match(value);
            if (rule != null) {
                if (isSsrfFalsePositiveHeader(name, rule)) {
                    continue;
                }
                String clientIp = getClientIp(request);
                // 记录详细日志
                try {
                        detailedViolationHandler.handleViolation(
                            value, value, rule, "header", name, clientIp, request
                        );
                    } catch (Exception e) {
                        log.error("Failed to record detailed violation", e);
                    }
                return rule;
            }
        }
        return null;
    }

    /**
     * 检查 Cookie 中的恶意输入
     * @param request HTTP 请求对象
     * @return 匹配到的规则名，未匹配到则返回 null
     */
    private String checkCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return null;
        }
        
        for (Cookie cookie : cookies) {
            if (cookie == null) {
                continue;
            }
            String name = cookie.getName();
            String value = cookie.getValue();
            
            // 检查 Cookie 名称
            if (name != null) {
                String rule = ruleEngine.match(name);
                if (rule != null) {
                    String clientIp = getClientIp(request);
                    try {
                        detailedViolationHandler.handleViolation(
                            name, name, rule, "cookie", name, clientIp, request
                        );
                    } catch (Exception e) {
                        log.error("Failed to record detailed violation", e);
                    }
                    return rule;
                }
            }
            
            if (value != null) {
                String rule = ruleEngine.match(value);
                if (rule != null) {
                    String clientIp = getClientIp(request);
                    try {
                        detailedViolationHandler.handleViolation(
                            value, value, rule, "cookie", name, clientIp, request
                        );
                    } catch (Exception e) {
                        log.error("Failed to record detailed violation", e);
                    }
                    return rule;
                }
            }
        }
        return null;
    }

    /**
     * 检查请求体中的恶意输入
     * @param request 缓存请求体的请求对象
     * @return 匹配到的规则名，未匹配到则返回 null
     */
    private String checkRequestBody(CachedBodyHttpServletRequest request) throws IOException {
        String contentType = request.getContentType();
        
        // 如果没有 Content-Type，跳过检测
        if (contentType == null) {
            return null;
        }

        // 仅检测文本类型的请求体
        if (contentType.contains("application/json") || 
            contentType.contains("application/xml") ||
            contentType.contains("text/xml") ||
            contentType.contains("text/plain") ||
            contentType.contains("application/x-www-form-urlencoded")) {
            
            String body = request.getCachedBody();
            if (body != null && !body.isEmpty()) {
                String rule = ruleEngine.match(body);
                if (rule != null) {
                    String clientIp = getClientIp(request);
                    try {
                        detailedViolationHandler.handleViolation(
                            body, body, rule, "body", "requestBody", clientIp, request
                        );
                    } catch (Exception e) {
                        log.error("Failed to record detailed violation", e);
                    }
                    return rule;
                }
            }
        }
        
        return null;
    }

    /**
     * 处理安全违规响应
     * 详细日志记录已在 detailedViolationHandler 中完成
     * @param ruleName 触发的规则名
     * @param source 输入来源（parameter/header/cookie/body）
     * @param url 请求 URL
     * @param method HTTP 方法
     * @param clientIp 客户端 IP
     * @param response HTTP 响应对象
     */
    private boolean handleViolation(String ruleName, String source, String url, String method, String clientIp, HttpServletResponse response)
            throws IOException {
        log.warn("Security violation detected - Rule: {}, Source: {}, IP: {}, URL: {}", ruleName, source, clientIp, url);

        if (properties.getMode() == InputSecurityProperties.Mode.BLOCK) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("application/json;charset=UTF-8");
            String escapedRuleName = escapeJson(ruleName);
            response.getWriter().write("{\"error\":\"Input blocked by security rule: " + escapedRuleName + "\"}");
            return true;
        }
        return false;
    }

    private boolean isSsrfFalsePositiveHeader(String headerName, String ruleName) {
        if (headerName == null || !"ssrf-attack".equalsIgnoreCase(ruleName)) {
            return false;
        }
        String normalized = headerName.trim().toLowerCase();
        return "referer".equals(normalized)
                || "origin".equals(normalized)
                || "host".equals(normalized)
                || "user-agent".equals(normalized);
    }
    
    private String escapeJson(String str) {
        if (str == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '<': sb.append("\\u003c"); break;
                case '>': sb.append("\\u003e"); break;
                case '&': sb.append("\\u0026"); break;
                default:
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
    
    /**
     * 获取客户端真实IP地址
     * 支持从X-Forwarded-For头获取代理前的真实IP
     * 包含IP欺骗防护机制
     * @param request HTTP请求对象
     * @return 客户端IP地址
     */
    private String getClientIp(HttpServletRequest request) {
        // 检查X-Forwarded-For头
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // 验证请求是否来自可信代理
            String remoteAddr = request.getRemoteAddr();
            
            // 如果配置了可信代理列表，且当前请求来自可信代理，则使用X-Forwarded-For
            if (isTrustedProxy(remoteAddr)) {
                // X-Forwarded-For可能包含多个IP，取第一个（最原始的客户端IP）
                String[] ips = xForwardedFor.split(",");
                if (ips.length > 0) {
                    String clientIp = ips[0].trim();
                    // 验证IP格式
                    if (isValidIp(clientIp)) {
                        return clientIp;
                    }
                }
            }
            // 如果不是可信代理，记录警告
            log.warn("X-Forwarded-For header from untrusted source: {}", remoteAddr);
        }
        
        // 返回直接连接的IP
        return request.getRemoteAddr();
    }
    
    /**
     * 检查IP是否来自可信代理
     * @param ip IP地址
     * @return 是否可信
     */
    private boolean isTrustedProxy(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        if (trustedProxies.isEmpty()) {
            if (ip.startsWith("127.") || ip.startsWith("10.") || 
                ip.startsWith("192.168.") || ip.equals("0:0:0:0:0:0:0:1") ||
                ip.equals("::1")) {
                return true;
            }
            if (ip.startsWith("172.")) {
                String[] parts = ip.split("\\.");
                if (parts.length >= 2) {
                    try {
                        int second = Integer.parseInt(parts[1]);
                        if (second >= 16 && second <= 31) {
                            return true;
                        }
                    } catch (NumberFormatException e) {
                        return false;
                    }
                }
                return false;
            }
            return false;
        }
        return trustedProxies.contains(ip);
    }
    
    /**
     * 验证IP地址格式是否有效
     * 使用 InetAddress 进行安全验证，避免正则绕过
     * @param ip IP地址
     * @return 是否有效
     */
    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        
        if (ip.length() > 45) {
            return false;
        }
        
        String normalizedIp = ip.trim().toLowerCase();
        
        if (normalizedIp.startsWith("[") && normalizedIp.endsWith("]")) {
            normalizedIp = normalizedIp.substring(1, normalizedIp.length() - 1);
        }
        
        for (char c : normalizedIp.toCharArray()) {
            if (!Character.isLetterOrDigit(c) && c != '.' && c != ':' && c != '-' && c != '%') {
                return false;
            }
        }
        
        try {
            java.net.InetAddress.getByName(normalizedIp);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 缓存请求体的HttpServletRequest包装类
     * 解决InputStream只能读取一次的问题，使请求体可被多次读取
     * 包含请求体大小限制，防止OOM攻击
     */
    private static class CachedBodyHttpServletRequest extends javax.servlet.http.HttpServletRequestWrapper {
        
        // 缓存的请求体字节数组
        private final byte[] cachedBody;
        // 是否因大小超限被截断
        private final boolean truncated;

        /**
         * 构造函数，读取并缓存请求体
         * @param request 原始请求对象
         * @param maxSize 最大允许的请求体大小
         * @throws IOException 读取失败时抛出
         */
        public CachedBodyHttpServletRequest(HttpServletRequest request, int maxSize) throws IOException {
            super(request);
            InputStream requestInputStream = request.getInputStream();
            
            // 读取请求体并检查大小限制
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int totalRead = 0;
            int n;
            boolean isTruncated = false;
            
            while ((n = requestInputStream.read(buffer)) != -1) {
                totalRead += n;
                if (totalRead > maxSize) {
                    // 超过大小限制，记录警告并截断
                    log.warn("Request body exceeds maximum size limit: {} bytes, truncated", maxSize);
                    isTruncated = true;
                    break;
                }
                output.write(buffer, 0, n);
            }
            
            this.cachedBody = output.toByteArray();
            this.truncated = isTruncated;
        }

        /**
         * 获取缓存的请求体字符串
         * @return 请求体字符串
         */
        public String getCachedBody() {
            return new String(cachedBody, StandardCharsets.UTF_8);
        }
        
        /**
         * 检查请求体是否被截断
         * @return 是否被截断
         */
        public boolean isTruncated() {
            return truncated;
        }
        
        /**
         * 获取请求体大小
         * @return 请求体字节数
         */
        public int getBodySize() {
            return cachedBody.length;
        }

        /**
         * 返回缓存的ServletInputStream
         */
        @Override
        public ServletInputStream getInputStream() throws IOException {
            return new CachedBodyServletInputStream(cachedBody);
        }

        /**
         * 返回缓存的BufferedReader
         */
        @Override
        public BufferedReader getReader() throws IOException {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }

        /**
         * 基于字节数组的ServletInputStream实现
         */
        private static class CachedBodyServletInputStream extends ServletInputStream {
            // 缓存的请求体数据
            private final byte[] cachedBody;
            // 当前读取位置
            private int lastIndexRetrieved = -1;
            // ReadListener（Servlet 3.1规范要求）
            private ReadListener readListener = null;

            public CachedBodyServletInputStream(byte[] cachedBody) {
                this.cachedBody = cachedBody;
            }

            /**
             * 判断是否已读取完毕
             */
            @Override
            public boolean isFinished() {
                return (lastIndexRetrieved == cachedBody.length - 1);
            }

            /**
             * 判断是否就绪
             */
            @Override
            public boolean isReady() {
                return true;
            }

            /**
             * 设置ReadListener
             */
            @Override
            public void setReadListener(ReadListener readListener) {
                this.readListener = readListener;
            }

            /**
             * 读取单个字节
             */
            @Override
            public int read() throws IOException {
                int i;
                if (!isFinished()) {
                    i = cachedBody[++lastIndexRetrieved];
                } else {
                    i = -1;
                }
                return i;
            }
        }
    }
}
