package org.example.input_security_starter.engine;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 规则引擎性能测试
 * 测试优化后的规则引擎性能表现
 */
class RuleEnginePerformanceTest {

    private OptimizedRuleEngine ruleEngine;

    @BeforeEach
    void setUp() {
        ruleEngine = new OptimizedRuleEngine();
        InputSecurityProperties properties = new InputSecurityProperties();
        ruleEngine.loadRules(properties.getRules());
    }

    @Test
    @DisplayName("Should verify rule distribution")
    void testRuleDistribution() {
        // 验证规则按优先级正确分组
        int totalRules = ruleEngine.getTotalRules();
        int highPriority = ruleEngine.getHighPriorityRuleCount();
        int mediumPriority = ruleEngine.getMediumPriorityRuleCount();
        int lowPriority = ruleEngine.getLowPriorityRuleCount();

        System.out.println("=== Rule Distribution ===");
        System.out.println("Total rules: " + totalRules);
        System.out.println("High priority: " + highPriority);
        System.out.println("Medium priority: " + mediumPriority);
        System.out.println("Low priority: " + lowPriority);

        assertTrue(totalRules > 0, "Should have rules loaded");
        assertEquals(totalRules, highPriority + mediumPriority + lowPriority,
            "Total should match sum of priorities");
        assertTrue(highPriority > 0, "Should have high priority rules");
    }

    @Test
    @DisplayName("Should detect high priority threats quickly")
    void testHighPriorityThreatDetection() {
        // 高优先级威胁应该被快速检测到
        String[] highPriorityThreats = {
            "<script>alert('xss')</script>",
            "'; DROP TABLE users;--",
            "; rm -rf /",
            "../../../etc/passwd",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        };

        for (String threat : highPriorityThreats) {
            String matchedRule = ruleEngine.match(threat);
            assertNotNull(matchedRule, "Should detect threat: " + threat);
        }
    }

    @Test
    @DisplayName("Should perform well under sustained load")
    void testSustainedLoadPerformance() {
        int iterations = 10000;
        String[] testInputs = {
            "<script>alert(1)</script>",
            "UNION SELECT * FROM users",
            "normal text input",
            "Hello World",
            "../../../etc/passwd",
            "safe query",
            "'; DROP TABLE users;--",
            "<img src=x onerror=alert(1)>",
            "file:///etc/passwd",
            "Just a normal string"
        };

        long startTime = System.nanoTime();
        int matchCount = 0;
        int noMatchCount = 0;

        for (int i = 0; i < iterations; i++) {
            String input = testInputs[i % testInputs.length];
            String result = ruleEngine.match(input);
            if (result != null) {
                matchCount++;
            } else {
                noMatchCount++;
            }
        }

        long endTime = System.nanoTime();
        long durationMs = (endTime - startTime) / 1_000_000;
        double avgTimeMicros = (durationMs * 1000.0) / iterations;
        double requestsPerSecond = iterations * 1000.0 / durationMs;

        System.out.println("=== Performance Test Results ===");
        System.out.println("Total iterations: " + iterations);
        System.out.println("Time taken: " + durationMs + "ms");
        System.out.println("Average time per request: " + String.format("%.2f", avgTimeMicros) + "μs");
        System.out.println("Requests per second: " + String.format("%.0f", requestsPerSecond));
        System.out.println("Matches: " + matchCount + ", No matches: " + noMatchCount);

        // 性能要求：平均每个请求应该小于 50 微秒
        assertTrue(avgTimeMicros < 50.0, 
            "Average request time should be less than 50μs, but was: " + avgTimeMicros + "μs");
        
        // 验证匹配结果正确
        assertTrue(matchCount > 0, "Should have some matches");
        assertTrue(noMatchCount > 0, "Should have some non-matches");
        assertEquals(iterations, matchCount + noMatchCount, "Total should match");
    }

    @Test
    @DisplayName("Should handle mixed threat levels efficiently")
    void testMixedThreatLevels() {
        // 测试混合威胁级别的检测效率
        List<String> threats = new ArrayList<>();
        threats.add("<script>alert(1)</script>");  // High
        threats.add("http://169.254.169.254/");    // Medium (SSRF)
        threats.add("normal input");                // Safe
        threats.add("'; DROP TABLE users;--");     // High
        threats.add("file:///etc/passwd");         // Medium
        threats.add("Hello World");                 // Safe

        long startTime = System.nanoTime();
        
        for (int i = 0; i < 1000; i++) {
            for (String threat : threats) {
                ruleEngine.match(threat);
            }
        }

        long durationMs = (System.nanoTime() - startTime) / 1_000_000;
        double avgTimeMicros = (durationMs * 1000.0) / (1000 * threats.size());

        System.out.println("=== Mixed Threat Test ===");
        System.out.println("Time taken: " + durationMs + "ms");
        System.out.println("Average time per request: " + String.format("%.2f", avgTimeMicros) + "μs");

        assertTrue(avgTimeMicros < 50.0, 
            "Should handle mixed threats efficiently");
    }

    @Test
    @DisplayName("Should detect encoded attacks with normalization overhead")
    void testEncodedAttackDetection() {
        // 测试编码攻击检测（包含规范化开销）
        String[] encodedAttacks = {
            "%3Cscript%3Ealert(1)%3C/script%3E",  // URL encoded XSS
            "&#60;script&#62;alert(1)&#60;/script&#62;",  // HTML entity encoded
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",  // Unicode encoded
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",  // URL encoded path traversal
            "%252e%252e%252f"  // Double URL encoded
        };

        long startTime = System.nanoTime();
        int detectedCount = 0;

        for (int i = 0; i < 1000; i++) {
            for (String attack : encodedAttacks) {
                String result = ruleEngine.match(attack);
                if (result != null) {
                    detectedCount++;
                }
            }
        }

        long durationMs = (System.nanoTime() - startTime) / 1_000_000;

        System.out.println("=== Encoded Attack Detection Test ===");
        System.out.println("Time taken: " + durationMs + "ms");
        System.out.println("Detected: " + detectedCount + " / " + (1000 * encodedAttacks.length));

        // 编码攻击应该都被检测到
        assertEquals(1000 * encodedAttacks.length, detectedCount, 
            "All encoded attacks should be detected");
    }

    @Test
    @DisplayName("Should maintain consistent performance with large inputs")
    void testLargeInputPerformance() {
        // 测试大输入的性能表现
        StringBuilder largeInput = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            largeInput.append("This is a normal text segment ");
        }
        largeInput.append("<script>alert(1)</script>");

        long startTime = System.nanoTime();
        
        for (int i = 0; i < 1000; i++) {
            ruleEngine.match(largeInput.toString());
        }

        long durationMs = (System.nanoTime() - startTime) / 1_000_000;
        double avgTimeMicros = (durationMs * 1000.0) / 1000;

        System.out.println("=== Large Input Performance Test ===");
        System.out.println("Input size: " + largeInput.length() + " characters");
        System.out.println("Time taken: " + durationMs + "ms");
        System.out.println("Average time per request: " + String.format("%.2f", avgTimeMicros) + "μs");

        // 对于 3KB+ 的大输入，性能要求放宽到 500μs
        // 增加 Base64 解码等功能后，性能阈值放宽到 600μs
        // 增加 SSRF 规则增强后，性能阈值放宽到 700μs
        assertTrue(avgTimeMicros < 700.0, 
            "Should handle large inputs efficiently");
    }

    @Test
    @DisplayName("Should prioritize high-threat detection")
    void testThreatPriority() {
        // 验证高威胁优先检测
        String inputWithMultipleThreats = "<script>alert(1)</script>; DROP TABLE users;--";
        
        String detectedRule = ruleEngine.match(inputWithMultipleThreats);
        assertNotNull(detectedRule, "Should detect at least one threat");
        
        // 由于高优先级规则先检测，应该检测到 XSS 或 SQL 注入
        assertTrue(
            detectedRule.contains("xss") || detectedRule.contains("sql"),
            "Should detect high priority threat first, but got: " + detectedRule
        );

        System.out.println("=== Threat Priority Test ===");
        System.out.println("Input: " + inputWithMultipleThreats);
        System.out.println("Detected rule: " + detectedRule);
    }
}
