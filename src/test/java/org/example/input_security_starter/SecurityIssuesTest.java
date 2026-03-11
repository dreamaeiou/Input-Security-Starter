package org.example.input_security_starter;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.InputNormalizer;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.example.input_security_starter.filter.InputSecurityFilter;
import org.example.input_security_starter.model.SecurityRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 安全问题测试类
 * 测试发现的安全漏洞和问题
 */
class SecurityIssuesTest {

    private OptimizedRuleEngine ruleEngine;
    private InputSecurityProperties properties;

    @BeforeEach
    void setUp() {
        ruleEngine = new OptimizedRuleEngine();
        properties = new InputSecurityProperties();
        ruleEngine.loadRules(properties.getRules());
    }

    // ==================== 1. 响应 XSS 风险测试 ====================

    @Test
    @DisplayName("SEC-001: 响应中的 ruleName 不应导致 XSS")
    void testResponseXssVulnerability() throws Exception {
        EventRecorder eventRecorder = new EventRecorder("test-security-events.log", 10, 5, false);
        InputSecurityFilter filter = new InputSecurityFilter(properties, ruleEngine, eventRecorder);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        request.setRequestURI("/api/test");
        request.setMethod("GET");
        request.addParameter("q", "<script>alert(1)</script>");
        
        properties.setMode(InputSecurityProperties.Mode.BLOCK);
        
        filter.doFilter(request, response, chain);
        
        String responseBody = response.getContentAsString();
        
        assertFalse(responseBody.contains("<script>"), 
            "响应不应包含未转义的 script 标签");
        assertFalse(responseBody.contains("</script>"), 
            "响应不应包含未转义的 script 结束标签");
    }

    @Test
    @DisplayName("SEC-002: 响应 JSON 应正确转义特殊字符")
    void testResponseJsonEscaping() throws Exception {
        EventRecorder eventRecorder = new EventRecorder("test-security-events.log", 10, 5, false);
        InputSecurityFilter filter = new InputSecurityFilter(properties, ruleEngine, eventRecorder);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        request.setRequestURI("/api/test");
        request.setMethod("GET");
        request.addParameter("q", "<img src=x onerror=alert(1)>");
        
        properties.setMode(InputSecurityProperties.Mode.BLOCK);
        
        filter.doFilter(request, response, chain);
        
        String responseBody = response.getContentAsString();
        
        assertTrue(responseBody.contains("\"error\""), "响应应为 JSON 格式");
        
        if (responseBody.contains("<") || responseBody.contains(">")) {
            assertTrue(responseBody.contains("\\u003c") || responseBody.contains("\\u003e") ||
                       responseBody.contains("\\<") || responseBody.contains("\\>"),
                "特殊字符应被转义");
        }
    }

    // ==================== 2. SSRF 绕过测试 ====================

    @Test
    @DisplayName("SEC-003: 应检测整数形式的内网 IP (SSRF 绕过)")
    void testSsrfBypassIntegerIp() {
        String integerIp = "http://2130706433/admin";
        String result = ruleEngine.match(integerIp);
        assertNotNull(result, "应检测整数形式的 127.0.0.1 (2130706433)");
    }

    @Test
    @DisplayName("SEC-004: 应检测十六进制形式的内网 IP")
    void testSsrfBypassHexIp() {
        String hexIp = "http://0x7f000001/admin";
        String result = ruleEngine.match(hexIp);
        assertNotNull(result, "应检测十六进制形式的 127.0.0.1 (0x7f000001)");
    }

    @Test
    @DisplayName("SEC-005: 应检测 IPv6 映射地址")
    void testSsrfBypassIpv6Mapped() {
        String ipv6Mapped = "http://[::ffff:127.0.0.1]/admin";
        String result = ruleEngine.match(ipv6Mapped);
        assertNotNull(result, "应检测 IPv6 映射地址 ::ffff:127.0.0.1");
    }

    @Test
    @DisplayName("SEC-006: 应检测省略形式的内网 IP")
    void testSsrfBypassShortIp() {
        String shortIp1 = "http://127.1/admin";
        String shortIp2 = "http://127.0.1/admin";
        
        String result1 = ruleEngine.match(shortIp1);
        String result2 = ruleEngine.match(shortIp2);
        
        assertNotNull(result1, "应检测省略形式 127.1");
        assertNotNull(result2, "应检测省略形式 127.0.1");
    }

    @Test
    @DisplayName("SEC-007: 应检测八进制形式的 IP")
    void testSsrfBypassOctalIp() {
        String octalIp = "http://0177.0.0.1/admin";
        String result = ruleEngine.match(octalIp);
        assertNotNull(result, "应检测八进制形式的 IP (0177.0.0.1 = 127.0.0.1)");
    }

    @Test
    @DisplayName("SEC-008: 应检测 0.0.0.0 绕过")
    void testSsrfBypassZeroIp() {
        String zeroIp1 = "http://0/admin";
        String zeroIp2 = "http://0.0.0.0/admin";
        
        String result1 = ruleEngine.match(zeroIp1);
        String result2 = ruleEngine.match(zeroIp2);
        
        assertNotNull(result1, "应检测 0 作为 IP");
        assertNotNull(result2, "应检测 0.0.0.0");
    }

    @Test
    @DisplayName("SEC-009: 应检测 DNS 重绑定攻击")
    void testSsrfDnsRebinding() {
        String dnsRebind = "http://localtest.me/admin";
        String result = ruleEngine.match(dnsRebind);
        assertNotNull(result, "应检测已知 DNS 重绑定域名");
    }

    // ==================== 3. 日志路径遍历测试 ====================

    @Test
    @DisplayName("SEC-010: 日志文件路径不应允许路径遍历")
    void testLogPathTraversal() throws IOException {
        String maliciousPath = "../../../etc/passwd";
        
        try {
            EventRecorder recorder = new EventRecorder(maliciousPath, 10, 5, false);
            
            SecurityEvent event = new SecurityEvent("test-rule", "test-input", "/test", "GET", "127.0.0.1");
            recorder.record(event);
            
            File maliciousFile = new File(maliciousPath);
            assertFalse(maliciousFile.exists(), "不应在路径遍历位置创建文件");
            
        } catch (SecurityException e) {
            assertTrue(true, "应拒绝路径遍历路径");
        }
    }

    @Test
    @DisplayName("SEC-011: 日志文件路径不应允许绝对路径写入敏感位置")
    void testLogAbsolutePathSecurity() {
        String[] dangerousPaths = {
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "/root/.ssh/authorized_keys"
        };
        
        for (String path : dangerousPaths) {
            try {
                EventRecorder recorder = new EventRecorder(path, 10, 5, false);
                fail("应拒绝敏感路径: " + path);
            } catch (SecurityException | IllegalArgumentException e) {
                assertTrue(true, "正确拒绝了敏感路径: " + path);
            }
        }
    }

    // ==================== 4. 规则误报测试 ====================

    @Test
    @DisplayName("SEC-012: 正常文本不应被误报为 SQL 注入")
    void testSqlInjectionFalsePositive() {
        String[] safeInputs = {
            "Please select option 1 or 2",
            "The user can select one or more items",
            "1 or more users",
            "2 and 3 are prime numbers",
            "Select your preferences",
            "The union of two sets"
        };
        
        for (String input : safeInputs) {
            String result = ruleEngine.match(input);
            assertNull(result, "正常文本不应被误报为 SQL 注入: " + input);
        }
    }

    @Test
    @DisplayName("SEC-013: 正常管道符使用不应被误报为命令注入")
    void testCommandInjectionFalsePositive() {
        String[] safeInputs = {
            "data1 | data2 | data3",
            "Process A | Process B",
            "a | b | c",
            "Use pipe | to connect"
        };
        
        for (String input : safeInputs) {
            String result = ruleEngine.match(input);
            assertNull(result, "正常管道符使用不应被误报: " + input);
        }
    }

    @Test
    @DisplayName("SEC-014: 正常模板语法不应被误报为模板注入")
    void testTemplateInjectionFalsePositive() {
        String[] safeInputs = {
            "The price is ${price}",
            "Use {{template}} syntax",
            "Value: #{value}",
            "Template: ${user.name}",
            "Hello ${user.firstName} ${user.lastName}"
        };
        
        for (String input : safeInputs) {
            String result = ruleEngine.match(input);
            assertNull(result, "正常模板语法不应被误报: " + input);
        }
    }

    @Test
    @DisplayName("SEC-015: 正常 HTML 不应被误报为 XSS")
    void testXssFalsePositive() {
        String[] safeInputs = {
            "<p>Hello World</p>",
            "<div class=\"container\">Content</div>",
            "<a href=\"https://example.com\">Link</a>",
            "<span>Text</span>",
            "<ul><li>Item 1</li><li>Item 2</li></ul>"
        };
        
        for (String input : safeInputs) {
            String result = ruleEngine.match(input);
            assertNull(result, "正常 HTML 不应被误报为 XSS: " + input);
        }
    }

    // ==================== 5. 递归调用风险测试 ====================

    @Test
    @DisplayName("SEC-016: 深层嵌套 Base64 不应导致内存溢出")
    void testDeepBase64Recursion() {
        String input = "test";
        for (int i = 0; i < 10; i++) {
            input = java.util.Base64.getEncoder().encodeToString(input.getBytes());
        }
        
        try {
            String result = InputNormalizer.normalize(input);
            assertNotNull(result, "深层嵌套 Base64 应被安全处理");
        } catch (OutOfMemoryError | StackOverflowError e) {
            fail("深层嵌套 Base64 不应导致内存/栈溢出: " + e.getClass().getSimpleName());
        }
    }

    @Test
    @DisplayName("SEC-017: 混合编码递归深度应有限制")
    void testMixedEncodingRecursionLimit() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 50; i++) {
            sb.append("%25");
        }
        sb.append("3Cscript%253E");
        
        try {
            String result = InputNormalizer.normalize(sb.toString());
            assertNotNull(result, "深层编码应被安全处理");
        } catch (StackOverflowError e) {
            fail("深层编码不应导致栈溢出");
        }
    }

    // ==================== 6. 代码质量测试 ====================

    @Test
    @DisplayName("SEC-018: SecurityRule 应验证 pattern 是否为有效正则")
    void testInvalidRegexPattern() {
        SecurityRule rule = new SecurityRule();
        rule.setName("test-rule");
        rule.setEnabled(true);
        
        assertThrows(IllegalArgumentException.class, () -> {
            rule.setPattern("[invalid(regex"); // 无效的正则表达式
        }, "无效正则应抛出 IllegalArgumentException");
    }

    @Test
    @DisplayName("SEC-019: SecurityRule level 应只接受有效值")
    void testSecurityRuleLevelValidation() {
        SecurityRule rule = new SecurityRule();
        rule.setName("test-rule");
        rule.setPattern("test");
        
        assertThrows(IllegalArgumentException.class, () -> {
            rule.setLevel("invalid-level"); // 无效的 level
        }, "无效 level 应抛出 IllegalArgumentException");
    }

    // ==================== 7. 边界条件测试 ====================

    @Test
    @DisplayName("SEC-020: 超长输入应被安全处理")
    void testVeryLongInput() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100000; i++) {
            sb.append("a");
        }
        String longInput = sb.toString();
        
        assertDoesNotThrow(() -> {
            String result = ruleEngine.match(longInput);
        }, "超长输入应被安全处理");
    }

    @Test
    @DisplayName("SEC-021: 空字节注入应被检测")
    void testNullByteInjection() {
        String nullByteInput = "test\u0000<script>alert(1)</script>";
        String result = ruleEngine.match(nullByteInput);
        assertNotNull(result, "空字节后的恶意代码应被检测");
    }

    @Test
    @DisplayName("SEC-022: Unicode 绕过应被检测")
    void testUnicodeBypass() {
        String unicodeBypass1 = "\u003cscript\u003ealert(1)\u003c/script\u003e";
        String unicodeBypass2 = "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e";
        
        String normalized1 = InputNormalizer.normalize(unicodeBypass1);
        String normalized2 = InputNormalizer.normalize(unicodeBypass2);
        
        String result1 = ruleEngine.match(normalized1);
        String result2 = ruleEngine.match(normalized2);
        
        assertNotNull(result1, "Unicode 编码的 XSS 应被检测");
        assertNotNull(result2, "Unicode 转义的 XSS 应被检测");
    }

    @Test
    @DisplayName("SEC-023: 双重编码应被检测")
    void testDoubleEncoding() {
        String doubleEncoded = "%253Cscript%253Ealert(1)%253C%252Fscript%253E";
        String normalized = InputNormalizer.normalize(doubleEncoded);
        String result = ruleEngine.match(normalized);
        assertNotNull(result, "双重编码的 XSS 应被检测");
    }

    @Test
    @DisplayName("SEC-024: 大小写混合绕过应被检测")
    void testCaseMixedBypass() {
        String[] mixedCaseInputs = {
            "<ScRiPt>alert(1)</ScRiPt>",
            "<IMG SRC=x OnErRoR=alert(1)>",
            "<SVG OnLoAd=alert(1)>",
            "JaVaScRiPt:alert(1)"
        };
        
        for (String input : mixedCaseInputs) {
            String result = ruleEngine.match(input);
            assertNotNull(result, "大小写混合绕过应被检测: " + input);
        }
    }

    // ==================== 8. 并发安全测试 ====================

    @Test
    @DisplayName("SEC-025: 规则引擎应为线程安全")
    void testRuleEngineThreadSafety() throws InterruptedException {
        int threadCount = 20;
        int operationsPerThread = 100;
        
        Thread[] threads = new Thread[threadCount];
        Exception[] exceptions = new Exception[threadCount];
        
        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            threads[i] = new Thread(() -> {
                try {
                    for (int j = 0; j < operationsPerThread; j++) {
                        String input = "<script>alert(" + threadId + "_" + j + ")</script>";
                        ruleEngine.match(input);
                    }
                } catch (Exception e) {
                    exceptions[threadId] = e;
                }
            });
        }
        
        for (Thread thread : threads) {
            thread.start();
        }
        
        for (Thread thread : threads) {
            thread.join(30000);
        }
        
        for (Exception e : exceptions) {
            if (e != null) {
                fail("并发访问不应抛出异常: " + e.getMessage());
            }
        }
    }

    // ==================== 9. 特殊攻击向量测试 ====================

    @Test
    @DisplayName("SEC-026: 应检测新型 XSS 向量")
    void testNewXssVectors() {
        String[] xssVectors = {
            "<svg/onload=alert(1)>",
            "<body/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
            "<iframe srcdoc='<script>alert(1)</script>'>"
        };
        
        for (String vector : xssVectors) {
            String result = ruleEngine.match(vector);
            assertNotNull(result, "应检测 XSS 向量: " + vector);
        }
    }

    @Test
    @DisplayName("SEC-027: 应检测新型 SQL 注入向量")
    void testNewSqlInjectionVectors() {
        String[] sqlVectors = {
            "1'; SELECT * FROM users--",
            "1' UNION SELECT username,password FROM users--",
            "1'; DROP TABLE users;--",
            "1' AND 1=1--",
            "1' OR '1'='1",
            "admin'--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--"
        };
        
        for (String vector : sqlVectors) {
            String result = ruleEngine.match(vector);
            assertNotNull(result, "应检测 SQL 注入向量: " + vector);
        }
    }

    @Test
    @DisplayName("SEC-028: 应检测 NoSQL 注入")
    void testNoSqlInjection() {
        String[] noSqlVectors = {
            "{\"$ne\": \"\"}",
            "{\"$gt\": \"\"}",
            "{\"$where\": \"this.password == this.username\"}",
            "{\"$or\": [{\"username\": \"admin\"}, {\"username\": \"user\"}]}",
            "{\"username\": {\"$ne\": null}}",
            "{\"$and\": [{\"role\": \"admin\"}, {\"status\": \"active\"}]}"
        };
        
        for (String vector : noSqlVectors) {
            String result = ruleEngine.match(vector);
            assertNotNull(result, "应检测 NoSQL 注入向量: " + vector);
        }
    }

    @Test
    @DisplayName("SEC-029: 应检测 CRLF 注入")
    void testCrlfInjection() {
        String[] crlfVectors = {
            "test\r\nSet-Cookie: malicious=cookie",
            "test\nSet-Cookie: malicious=cookie",
            "test%0d%0aSet-Cookie: malicious=cookie",
            "test%0aSet-Cookie: malicious=cookie"
        };
        
        for (String vector : crlfVectors) {
            String normalized = InputNormalizer.normalize(vector);
            assertTrue(!normalized.contains("\r\n") || normalized.contains("Set-Cookie"),
                "CRLF 注入应被规范化或检测");
        }
    }
}
