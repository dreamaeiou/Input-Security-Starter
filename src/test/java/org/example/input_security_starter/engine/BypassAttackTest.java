package org.example.input_security_starter.engine;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.model.SecurityRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 绕过攻击测试
 * 测试各种编码绕过技巧是否能被正确检测
 */
class BypassAttackTest {

    private OptimizedRuleEngine ruleEngine;

    @BeforeEach
    void setUp() {
        ruleEngine = new OptimizedRuleEngine();
        InputSecurityProperties properties = new InputSecurityProperties();
        ruleEngine.loadRules(properties.getRules());
    }

    // ==================== XSS绕过测试 ====================

    @Test
    @DisplayName("Should detect basic XSS")
    void testBasicXss() {
        assertNotNull(ruleEngine.match("<script>alert(1)</script>"));
    }

    @Test
    @DisplayName("Should detect XSS with case variation")
    void testCaseVariationXss() {
        assertNotNull(ruleEngine.match("<SCRIPT>alert(1)</SCRIPT>"));
        assertNotNull(ruleEngine.match("<ScRiPt>alert(1)</ScRiPt>"));
        assertNotNull(ruleEngine.match("<sCrIpT>alert(1)</sCrIpT>"));
    }

    @Test
    @DisplayName("Should detect XSS with URL encoding")
    void testUrlEncodedXss() {
        assertNotNull(ruleEngine.match("%3Cscript%3Ealert(1)%3C/script%3E"));
        assertNotNull(ruleEngine.match("%3cscript%3ealert(1)%3c/script%3e"));
    }

    @Test
    @DisplayName("Should detect XSS with double URL encoding")
    void testDoubleUrlEncodedXss() {
        assertNotNull(ruleEngine.match("%253Cscript%253Ealert(1)%253C/script%253E"));
    }

    @Test
    @DisplayName("Should detect XSS with HTML entity encoding")
    void testHtmlEntityEncodedXss() {
        assertNotNull(ruleEngine.match("&#60;script&#62;alert(1)&#60;/script&#62;"));
        assertNotNull(ruleEngine.match("&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;"));
    }

    @Test
    @DisplayName("Should detect XSS with Unicode encoding")
    void testUnicodeEncodedXss() {
        assertNotNull(ruleEngine.match("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"));
    }

    @Test
    @DisplayName("Should detect XSS with whitespace variations")
    void testWhitespaceVariationXss() {
        assertNotNull(ruleEngine.match("<script\t>alert(1)</script\n>"));
        assertNotNull(ruleEngine.match("<script\r>alert(1)</script\r\n>"));
        assertNotNull(ruleEngine.match("< script>alert(1)</script>"));
        assertNotNull(ruleEngine.match("<script >alert(1)</script >"));
    }

    @Test
    @DisplayName("Should detect XSS with null bytes")
    void testNullByteXss() {
        assertNotNull(ruleEngine.match("<scr\u0000ipt>alert(1)</sc\u0000ript>"));
    }

    @Test
    @DisplayName("Should detect event handler XSS")
    void testEventHandlerXss() {
        assertNotNull(ruleEngine.match("<img src=x onerror=alert(1)>"));
        assertNotNull(ruleEngine.match("<body onload=alert(1)>"));
        assertNotNull(ruleEngine.match("<svg onload=alert(1)>"));
        assertNotNull(ruleEngine.match("<div onmouseover=alert(1)>"));
    }

    @Test
    @DisplayName("Should detect javascript: protocol XSS")
    void testJavascriptProtocolXss() {
        assertNotNull(ruleEngine.match("<a href=\"javascript:alert(1)\">"));
        assertNotNull(ruleEngine.match("<a href=\"JAVASCRIPT:alert(1)\">"));
        assertNotNull(ruleEngine.match("<a href=\"JaVaScRiPt:alert(1)\">"));
    }

    @Test
    @DisplayName("Should detect data: URI XSS")
    void testDataUriXss() {
        assertNotNull(ruleEngine.match("<a href=\"data:text/html,<script>alert(1)</script>\">"));
        assertNotNull(ruleEngine.match("<iframe src=\"data:text/html,<script>alert(1)</script>\">"));
    }

    @Test
    @DisplayName("Should detect SVG XSS")
    void testSvgXss() {
        assertNotNull(ruleEngine.match("<svg><script>alert(1)</script></svg>"));
        assertNotNull(ruleEngine.match("<svg onload=alert(1)>"));
    }

    @Test
    @DisplayName("Should detect iframe XSS")
    void testIframeXss() {
        assertNotNull(ruleEngine.match("<iframe src=\"javascript:alert(1)\">"));
        assertNotNull(ruleEngine.match("<iframe src=\"evil.html\">"));
    }

    @Test
    @DisplayName("Should detect expression XSS (IE)")
    void testExpressionXss() {
        assertNotNull(ruleEngine.match("<div style=\"background:expression(alert(1))\">"));
        assertNotNull(ruleEngine.match("<style>body{background:expression(alert(1))}</style>"));
    }

    // ==================== SQL注入绕过测试 ====================

    @Test
    @DisplayName("Should detect basic SQL injection")
    void testBasicSqlInjection() {
        assertNotNull(ruleEngine.match("' OR '1'='1"));
        assertNotNull(ruleEngine.match("1' OR '1'='1' --"));
        assertNotNull(ruleEngine.match("admin'--"));
    }

    @Test
    @DisplayName("Should detect UNION SELECT injection")
    void testUnionSelectInjection() {
        assertNotNull(ruleEngine.match("' UNION SELECT * FROM users--"));
        assertNotNull(ruleEngine.match("1 UNION SELECT username, password FROM users"));
        assertNotNull(ruleEngine.match("' UNION ALL SELECT null--"));
    }

    @Test
    @DisplayName("Should detect SQL injection with case variation")
    void testCaseVariationSqlInjection() {
        assertNotNull(ruleEngine.match("' union select * from users--"));
        assertNotNull(ruleEngine.match("' UnIoN SeLeCt * FrOm users--"));
        assertNotNull(ruleEngine.match("' UNION SELECT * FROM USERS--"));
    }

    @Test
    @DisplayName("Should detect SQL injection with comments")
    void testSqlInjectionWithComments() {
        assertNotNull(ruleEngine.match("admin'--"));
        assertNotNull(ruleEngine.match("admin'#"));
        assertNotNull(ruleEngine.match("admin'/*comment*/"));
    }

    @Test
    @DisplayName("Should detect time-based blind SQL injection")
    void testTimeBasedSqlInjection() {
        assertNotNull(ruleEngine.match("' AND SLEEP(5)--"));
        assertNotNull(ruleEngine.match("' AND BENCHMARK(10000000,SHA1('test'))--"));
        assertNotNull(ruleEngine.match("'; WAITFOR DELAY '0:0:5'--"));
    }

    @Test
    @DisplayName("Should detect stacked queries")
    void testStackedQueries() {
        assertNotNull(ruleEngine.match("'; DROP TABLE users;--"));
        assertNotNull(ruleEngine.match("'; INSERT INTO users VALUES(1,'hacker');--"));
    }

    @Test
    @DisplayName("Should detect hex encoding SQL injection")
    void testHexEncodingSqlInjection() {
        assertNotNull(ruleEngine.match("0x74657374"));
    }

    @Test
    @DisplayName("Should detect CHAR function injection")
    void testCharFunctionInjection() {
        assertNotNull(ruleEngine.match("CHAR(60,115,99,114,105,112,116,62)"));
    }

    @Test
    @DisplayName("Should detect MySQL file operations")
    void testMySqlFileOperations() {
        assertNotNull(ruleEngine.match("LOAD_FILE('/etc/passwd')"));
        assertNotNull(ruleEngine.match("INTO OUTFILE '/var/www/shell.php'"));
    }

    @Test
    @DisplayName("Should detect stored procedure injection")
    void testStoredProcedureInjection() {
        assertNotNull(ruleEngine.match("xp_cmdshell('dir')"));
        assertNotNull(ruleEngine.match("sp_executesql N'SELECT * FROM users'"));
    }

    // ==================== 命令注入绕过测试 ====================

    @Test
    @DisplayName("Should detect basic command injection")
    void testBasicCommandInjection() {
        assertNotNull(ruleEngine.match("; ls -la"));
        assertNotNull(ruleEngine.match("| cat /etc/passwd"));
        assertNotNull(ruleEngine.match("&& whoami"));
        assertNotNull(ruleEngine.match("|| id"));
    }

    @Test
    @DisplayName("Should detect command injection with backticks")
    void testBacktickCommandInjection() {
        assertNotNull(ruleEngine.match("`cat /etc/passwd`"));
        assertNotNull(ruleEngine.match("echo `whoami`"));
    }

    @Test
    @DisplayName("Should detect command injection with $()")
    void testDollarCommandInjection() {
        assertNotNull(ruleEngine.match("$(cat /etc/passwd)"));
        assertNotNull(ruleEngine.match("echo $(whoami)"));
    }

    @Test
    @DisplayName("Should detect Windows command injection")
    void testWindowsCommandInjection() {
        assertNotNull(ruleEngine.match("| dir"));
        assertNotNull(ruleEngine.match("| type C:\\Windows\\System32\\config\\SAM"));
        assertNotNull(ruleEngine.match("; rm -rf /"));
        assertNotNull(ruleEngine.match("cmd.exe /c dir"));
    }

    @Test
    @DisplayName("Should detect command injection with URL encoding")
    void testUrlEncodedCommandInjection() {
        assertNotNull(ruleEngine.match("%3Bls%20-la"));
        assertNotNull(ruleEngine.match("%7Ccat%20/etc/passwd"));
    }

    // ==================== 路径遍历绕过测试 ====================

    @Test
    @DisplayName("Should detect basic path traversal")
    void testBasicPathTraversal() {
        assertNotNull(ruleEngine.match("../../../etc/passwd"));
        assertNotNull(ruleEngine.match("..\\..\\..\\windows\\system32\\config\\sam"));
    }

    @Test
    @DisplayName("Should detect URL encoded path traversal")
    void testUrlEncodedPathTraversal() {
        assertNotNull(ruleEngine.match("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"));
        assertNotNull(ruleEngine.match("..%2f..%2f..%2fetc/passwd"));
    }

    @Test
    @DisplayName("Should detect double URL encoded path traversal")
    void testDoubleUrlEncodedPathTraversal() {
        assertNotNull(ruleEngine.match("%252e%252e%252f%252e%252e%252fetc/passwd"));
    }

    @Test
    @DisplayName("Should detect UTF-8 encoded path traversal")
    void testUtf8EncodedPathTraversal() {
        assertNotNull(ruleEngine.match("%c0%ae%c0%ae%c0%afetc/passwd"));
        assertNotNull(ruleEngine.match("%uff0e%uff0e%uff0fetc/passwd"));
    }

    // ==================== SSRF绕过测试 ====================

    @Test
    @DisplayName("Should detect basic SSRF")
    void testBasicSsrf() {
        assertNotNull(ruleEngine.match("file:///etc/passwd"));
        assertNotNull(ruleEngine.match("http://127.0.0.1/admin"));
        assertNotNull(ruleEngine.match("http://localhost:8080"));
    }

    @Test
    @DisplayName("Should detect SSRF with internal IP")
    void testInternalIpSsrf() {
        assertNotNull(ruleEngine.match("http://10.0.0.1/"));
        assertNotNull(ruleEngine.match("http://172.16.0.1/"));
        assertNotNull(ruleEngine.match("http://192.168.1.1/"));
    }

    @Test
    @DisplayName("Should detect SSRF with protocol variation")
    void testProtocolVariationSsrf() {
        assertNotNull(ruleEngine.match("FILE:///etc/passwd"));
        assertNotNull(ruleEngine.match("File:///etc/passwd"));
        assertNotNull(ruleEngine.match("gopher://internal-host:70/"));
        assertNotNull(ruleEngine.match("dict://internal-host:11211/stat"));
    }

    @Test
    @DisplayName("Should detect cloud metadata SSRF")
    void testCloudMetadataSsrf() {
        assertNotNull(ruleEngine.match("http://169.254.169.254/latest/meta-data/"));
        assertNotNull(ruleEngine.match("http://metadata.google.internal/"));
    }

    // ==================== XXE绕过测试 ====================

    @Test
    @DisplayName("Should detect basic XXE")
    void testBasicXxe() {
        assertNotNull(ruleEngine.match("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"));
        assertNotNull(ruleEngine.match("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"));
    }

    @Test
    @DisplayName("Should detect XXE with parameter entity")
    void testParameterEntityXxe() {
        assertNotNull(ruleEngine.match("<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">]>"));
    }

    @Test
    @DisplayName("Should detect XXE with case variation")
    void testCaseVariationXxe() {
        assertNotNull(ruleEngine.match("<!doctype foo [<!entity xxe SYSTEM \"file:///etc/passwd\">]>"));
        assertNotNull(ruleEngine.match("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"));
    }

    // ==================== 模板注入测试 ====================

    @Test
    @DisplayName("Should detect template injection")
    void testTemplateInjection() {
        assertNotNull(ruleEngine.match("${7*7}"));
        assertNotNull(ruleEngine.match("{{7*7}}"));
        assertNotNull(ruleEngine.match("#{7*7}"));
    }

    @Test
    @DisplayName("Should detect Freemarker injection")
    void testFreemarkerInjection() {
        assertNotNull(ruleEngine.match("${\"freemarker.template.utility.Execute\"?new()(\"id\")}"));
    }

    @Test
    @DisplayName("Should detect expression language injection")
    void testExpressionLanguageInjection() {
        assertNotNull(ruleEngine.match("${runtime.exec('id')}"));
        assertNotNull(ruleEngine.match("${T(java.lang.Runtime).getRuntime()}"));
    }

    // ==================== 反序列化攻击测试 ====================

    @Test
    @DisplayName("Should detect Java serialization")
    void testJavaSerialization() {
        assertNotNull(ruleEngine.match("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="));
        assertNotNull(ruleEngine.match("aced0005"));
    }

    @Test
    @DisplayName("Should detect PHP serialization")
    void testPhpSerialization() {
        assertNotNull(ruleEngine.match("O:8:\"stdClass\":1:{s:3:\"foo\";s:3:\"bar\";}"));
        assertNotNull(ruleEngine.match("a:1:{s:3:\"key\";s:5:\"value\";}"));
    }

    @Test
    @DisplayName("Should detect dangerous deserialization classes")
    void testDangerousDeserializationClasses() {
        assertNotNull(ruleEngine.match("org.apache.commons.collections.functors.InvokerTransformer"));
    }

    // ==================== 安全输入测试 ====================

    @Test
    @DisplayName("Should not block safe input")
    void testSafeInput() {
        assertNull(ruleEngine.match("Hello, World!"));
        assertNull(ruleEngine.match("This is a normal text message."));
        assertNull(ruleEngine.match("user@example.com"));
        assertNull(ruleEngine.match("https://www.google.com"));
    }

    @Test
    @DisplayName("Should not block safe HTML")
    void testSafeHtml() {
        assertNull(ruleEngine.match("<p>Hello</p>"));
        assertNull(ruleEngine.match("<div class=\"container\">Content</div>"));
        assertNull(ruleEngine.match("<a href=\"https://example.com\">Link</a>"));
    }

    @Test
    @DisplayName("Should not block safe SQL keywords in context")
    void testSafeSqlKeywords() {
        assertNull(ruleEngine.match("Please select an option"));
        assertNull(ruleEngine.match("The union of two sets"));
    }
}
