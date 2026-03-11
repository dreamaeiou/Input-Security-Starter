package org.example.input_security_starter.filter;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.model.SecurityRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class InputSecurityFilterTest {

    private InputSecurityFilter filter;
    private InputSecurityProperties properties;
    private OptimizedRuleEngine ruleEngine;
    private EventRecorder eventRecorder;

    @BeforeEach
    void setUp() {
        properties = new InputSecurityProperties();
        properties.setEnabled(true);
        properties.setMode(InputSecurityProperties.Mode.BLOCK);
        
        ruleEngine = new OptimizedRuleEngine();
        List<SecurityRule> rules = createTestRules();
        ruleEngine.loadRules(rules);
        
        eventRecorder = new EventRecorder();
        filter = new InputSecurityFilter(properties, ruleEngine, eventRecorder);
    }

    // ==================== 基本功能测试 ====================

    @Test
    @DisplayName("Should allow safe request")
    void testSafeRequest() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addParameter("name", "John");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should block XSS in parameter")
    void testXssInParameter() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/search");
        request.setMethod("GET");
        request.addParameter("q", "<script>alert('xss')</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("xss-attack"));
    }

    @Test
    @DisplayName("Should block SQL injection in parameter")
    void testSqlInjectionInParameter() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addParameter("id", "1 UNION SELECT * FROM users");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("sql-injection"));
    }

    @Test
    @DisplayName("Should block malicious header")
    void testMaliciousHeader() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addHeader("X-Custom-Header", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should block malicious cookie")
    void testMaliciousCookie() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setCookies(new javax.servlet.http.Cookie("session", "<script>alert(1)</script>"));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should block malicious cookie value")
    void testMaliciousCookieValue() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setCookies(new javax.servlet.http.Cookie("session", "union select * from users"));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should block malicious JSON body")
    void testMaliciousJsonBody() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("POST");
        request.setContentType("application/json");
        String maliciousJson = "{\"name\": \"<script>alert(1)</script>\", \"email\": \"test@test.com\"}";
        request.setContent(maliciousJson.getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should block malicious XML body")
    void testMaliciousXmlBody() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("POST");
        request.setContentType("application/xml");
        String maliciousXml = "<user><name>UNION SELECT password FROM users</name></user>";
        request.setContent(maliciousXml.getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should allow safe JSON body")
    void testSafeJsonBody() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("POST");
        request.setContentType("application/json");
        String safeJson = "{\"name\": \"John Doe\", \"email\": \"john@example.com\"}";
        request.setContent(safeJson.getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should skip internal UI paths")
    void testSkipInternalPaths() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/input-security-view/test");
        request.setMethod("GET");
        request.addParameter("input", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should skip excluded paths - exact match")
    void testSkipExcludedPathsExactMatch() throws IOException, ServletException {
        properties.setExcludePaths(Arrays.asList("/favicon.ico", "/health"));
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/favicon.ico");
        request.setMethod("GET");
        // 添加恶意 header，如果排除生效则不应被拦截
        request.addHeader("X-Custom", "http://127.0.0.1");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus(), "Excluded path should not be blocked");
    }

    @Test
    @DisplayName("Should skip excluded paths - Ant style /**")
    void testSkipExcludedPathsAntStyle() throws IOException, ServletException {
        properties.setExcludePaths(Arrays.asList("/static/**", "/resources/**"));
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/static/js/app.js");
        request.setMethod("GET");
        request.addHeader("X-Custom", "http://127.0.0.1");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus(), "Ant-style excluded path should not be blocked");
    }

    @Test
    @DisplayName("Should skip excluded paths - prefix match")
    void testSkipExcludedPathsPrefixMatch() throws IOException, ServletException {
        properties.setExcludePaths(Arrays.asList("/css/", "/js/"));
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/css/main.css");
        request.setMethod("GET");
        request.addHeader("X-Custom", "http://127.0.0.1");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus(), "Prefix excluded path should not be blocked");
    }

    @Test
    @DisplayName("Should not skip non-excluded paths")
    void testNotSkipNonExcludedPaths() throws IOException, ServletException {
        properties.setExcludePaths(Arrays.asList("/favicon.ico", "/static/**"));
        properties.setMode(InputSecurityProperties.Mode.BLOCK);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus(), "Non-excluded path with attack should be blocked");
    }

    @Test
    @DisplayName("Should skip when disabled")
    void testDisabledFilter() throws IOException, ServletException {
        properties.setEnabled(false);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should allow in monitor mode")
    void testMonitorMode() throws IOException, ServletException {
        properties.setMode(InputSecurityProperties.Mode.MONITOR);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
        assertEquals(1, eventRecorder.getRecentEvents(10).size());
    }

    @Test
    @DisplayName("Should handle path traversal attack")
    void testPathTraversal() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/files");
        request.setMethod("GET");
        request.addParameter("path", "../../../etc/passwd");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should handle command injection attack")
    void testCommandInjection() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/exec");
        request.setMethod("POST");
        request.setContentType("application/json");
        String maliciousBody = "{\"cmd\": \"ls; cat /etc/passwd\"}";
        request.setContent(maliciousBody.getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should skip body check for non-text content types")
    void testNonTextContentType() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/upload");
        request.setMethod("POST");
        request.setContentType("multipart/form-data");
        String body = "some binary data";
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should handle null content type")
    void testNullContentType() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/upload");
        request.setMethod("POST");
        request.setContentType(null);
        String body = "some data";
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    // ==================== IP 可信验证测试 ====================

    @Test
    @DisplayName("Should trust X-Forwarded-For from local IP")
    void testTrustedProxyLocalIp() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "192.168.1.100, 10.0.0.1");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        assertEquals("192.168.1.100", events.get(0).getIpAddress());
    }

    @Test
    @DisplayName("Should trust X-Forwarded-For from private IP 10.x")
    void testTrustedProxyPrivateIp10() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "8.8.8.8");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        assertEquals("8.8.8.8", events.get(0).getIpAddress());
    }

    @Test
    @DisplayName("Should trust X-Forwarded-For from private IP 192.168.x")
    void testTrustedProxyPrivateIp192() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("192.168.1.1");
        request.addHeader("X-Forwarded-For", "203.0.113.50");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        assertEquals("203.0.113.50", events.get(0).getIpAddress());
    }

    @Test
    @DisplayName("Should NOT trust X-Forwarded-For from external IP")
    void testUntrustedProxyExternalIp() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("203.0.113.50");
        request.addHeader("X-Forwarded-For", "8.8.8.8");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        // 应该使用直接连接的IP，而不是伪造的X-Forwarded-For
        assertEquals("203.0.113.50", events.get(0).getIpAddress());
    }

    @Test
    @DisplayName("Should use configured trusted proxies")
    void testConfiguredTrustedProxies() throws IOException, ServletException {
        // 创建带配置可信代理的过滤器
        List<String> trustedProxies = Arrays.asList("10.0.0.100", "10.0.0.101");
        InputSecurityFilter filterWithTrustedProxies = new InputSecurityFilter(
            properties, ruleEngine, eventRecorder, trustedProxies);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.100");
        request.addHeader("X-Forwarded-For", "1.2.3.4");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filterWithTrustedProxies.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        assertEquals("1.2.3.4", events.get(0).getIpAddress());
    }

    @Test
    @DisplayName("Should NOT trust private IP when configured trusted proxies exist")
    void testPrivateIpNotTrustedWhenConfigured() throws IOException, ServletException {
        // 创建带配置可信代理的过滤器
        List<String> trustedProxies = Arrays.asList("10.0.0.100");
        InputSecurityFilter filterWithTrustedProxies = new InputSecurityFilter(
            properties, ruleEngine, eventRecorder, trustedProxies);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("192.168.1.1");  // 私有IP但不在配置列表中
        request.addHeader("X-Forwarded-For", "8.8.8.8");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filterWithTrustedProxies.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        // 应该使用直接连接的IP
        assertEquals("192.168.1.1", events.get(0).getIpAddress());
    }

    @Test
    @DisplayName("Should handle empty X-Forwarded-For")
    void testEmptyXForwardedFor() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        assertEquals("127.0.0.1", events.get(0).getIpAddress());
    }

    @Test
    @DisplayName("Should use remote addr when no X-Forwarded-For")
    void testNoXForwardedFor() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.50");
        request.addParameter("q", "<script>alert(1)</script>");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        List<org.example.input_security_starter.event.SecurityEvent> events = eventRecorder.getRecentEvents(10);
        assertEquals(1, events.size());
        assertEquals("10.0.0.50", events.get(0).getIpAddress());
    }

    // ==================== 空指针防护测试 ====================

    @Test
    @DisplayName("Should handle empty parameter map")
    void testEmptyParameterMap() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        // 不添加任何参数
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should handle null cookies")
    void testNullCookies() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        // 不设置cookies
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should handle empty cookies array")
    void testEmptyCookiesArray() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setCookies(new javax.servlet.http.Cookie[0]);
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should handle empty request body")
    void testEmptyRequestBody() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("POST");
        request.setContentType("application/json");
        request.setContent(new byte[0]);
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    // ==================== 请求体大小限制测试 ====================

    @Test
    @DisplayName("Should handle large request body")
    void testLargeRequestBody() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/upload");
        request.setMethod("POST");
        request.setContentType("application/json");
        
        // 创建一个大的JSON body (但不超过10MB限制)
        StringBuilder sb = new StringBuilder("{\"data\": \"");
        for (int i = 0; i < 1000; i++) {
            sb.append("x");
        }
        sb.append("\"}");
        request.setContent(sb.toString().getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should handle text/plain content type")
    void testTextPlainContentType() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/text");
        request.setMethod("POST");
        request.setContentType("text/plain");
        request.setContent("Hello World".getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should handle application/x-www-form-urlencoded content type")
    void testFormUrlencodedContentType() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/form");
        request.setMethod("POST");
        request.setContentType("application/x-www-form-urlencoded");
        request.setContent("foo=bar".getBytes(StandardCharsets.UTF_8));
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filter.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    // ==================== 构造函数测试 ====================

    @Test
    @DisplayName("Should work with null trusted proxies list")
    void testNullTrustedProxiesList() throws IOException, ServletException {
        InputSecurityFilter filterWithNull = new InputSecurityFilter(
            properties, ruleEngine, eventRecorder, null);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addParameter("name", "John");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filterWithNull.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("Should work with empty trusted proxies list")
    void testEmptyTrustedProxiesList() throws IOException, ServletException {
        InputSecurityFilter filterWithEmpty = new InputSecurityFilter(
            properties, ruleEngine, eventRecorder, Collections.emptyList());
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.addParameter("name", "John");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        filterWithEmpty.doFilter(request, response, chain);
        
        assertEquals(200, response.getStatus());
    }

    // ==================== 辅助方法 ====================

    private List<SecurityRule> createTestRules() {
        List<SecurityRule> rules = new ArrayList<>();
        
        rules.add(createRule("xss-attack", 
            "(?i)(<\\s*script[^>]*>|</\\s*script\\s*>|on\\w+\\s*=|javascript:)", 
            "high", true));
        
        rules.add(createRule("sql-injection", 
            "(?i)\\bunion\\s+(?:all\\s+)?select\\b", 
            "high", true));
        
        rules.add(createRule("command-injection", 
            "(?i)(;|\\||&|`|\\$\\(|\\$\\{)", 
            "high", true));
        
        rules.add(createRule("path-traversal", 
            "(?i)(\\.\\.[/\\\\])", 
            "high", true));
        
        return rules;
    }

    private SecurityRule createRule(String name, String pattern, String level, boolean enabled) {
        SecurityRule rule = new SecurityRule();
        rule.setName(name);
        rule.setPattern(pattern);
        rule.setLevel(level);
        rule.setEnabled(enabled);
        return rule;
    }
}
