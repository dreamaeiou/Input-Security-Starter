package org.example.input_security_starter.engine;

import org.example.input_security_starter.model.SecurityRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OptimizedRuleEngineTest {

    private OptimizedRuleEngine ruleEngine;
    private List<SecurityRule> rules;

    @BeforeEach
    void setUp() {
        ruleEngine = new OptimizedRuleEngine();
        rules = new ArrayList<>();
        
        rules.add(createRule("xss-script-tag", "<script[^>]*>.*?</script>", "high", true));
        rules.add(createRule("sql-union-select", "union\\s+select", "high", true));
        rules.add(createRule("command-injection", "(;|\\||&|`|\\$\\(|\\$\\{)", "medium", true));
        rules.add(createRule("path-traversal", "\\.\\.[\\\\/]", "high", true));
        rules.add(createRule("disabled-rule", "should-not-match", "low", false));
        
        ruleEngine.loadRules(rules);
    }

    @Test
    @DisplayName("Should match XSS script tag")
    void testXssScriptTagDetection() {
        String result = ruleEngine.match("<script>alert('xss')</script>");
        assertNotNull(result);
        assertEquals("xss-script-tag", result);
    }

    @Test
    @DisplayName("Should match SQL injection")
    void testSqlInjectionDetection() {
        String result = ruleEngine.match("SELECT * FROM users UNION SELECT * FROM admin");
        assertNotNull(result);
        assertEquals("sql-union-select", result);
    }

    @Test
    @DisplayName("Should match command injection")
    void testCommandInjectionDetection() {
        String result = ruleEngine.match("test; rm -rf /");
        assertNotNull(result);
        assertEquals("command-injection", result);
    }

    @Test
    @DisplayName("Should match path traversal")
    void testPathTraversalDetection() {
        String result = ruleEngine.match("../../../etc/passwd");
        assertNotNull(result);
        assertEquals("path-traversal", result);
    }

    @Test
    @DisplayName("Should not match safe input")
    void testSafeInput() {
        String result = ruleEngine.match("Hello, World!");
        assertNull(result);
    }

    @Test
    @DisplayName("Should not match disabled rule")
    void testDisabledRule() {
        String result = ruleEngine.match("should-not-match");
        assertNull(result);
    }

    @Test
    @DisplayName("Should return null for null input")
    void testNullInput() {
        String result = ruleEngine.match(null);
        assertNull(result);
    }

    @Test
    @DisplayName("Should return null for empty input")
    void testEmptyInput() {
        String result = ruleEngine.match("");
        assertNull(result);
    }

    @Test
    @DisplayName("Should prioritize high level rules")
    void testPriorityOrder() {
        List<SecurityRule> priorityRules = new ArrayList<>();
        priorityRules.add(createRule("low-rule", "test", "low", true));
        priorityRules.add(createRule("high-rule", "test", "high", true));
        priorityRules.add(createRule("medium-rule", "test", "medium", true));
        
        OptimizedRuleEngine priorityEngine = new OptimizedRuleEngine();
        priorityEngine.loadRules(priorityRules);
        
        String result = priorityEngine.match("test");
        assertNotNull(result);
        assertEquals("high-rule", result);
    }

    @Test
    @DisplayName("Should handle case insensitive matching")
    void testCaseInsensitive() {
        String result1 = ruleEngine.match("<SCRIPT>alert(1)</SCRIPT>");
        String result2 = ruleEngine.match("<Script>alert(1)</Script>");
        assertNotNull(result1);
        assertNotNull(result2);
    }

    @Test
    @DisplayName("Should load empty rules list")
    void testEmptyRules() {
        OptimizedRuleEngine emptyEngine = new OptimizedRuleEngine();
        emptyEngine.loadRules(new ArrayList<>());
        
        String result = emptyEngine.match("<script>alert(1)</script>");
        assertNull(result);
    }

    @Test
    @DisplayName("Should handle null rules list")
    void testNullRules() {
        OptimizedRuleEngine nullEngine = new OptimizedRuleEngine();
        nullEngine.loadRules(null);
        
        String result = nullEngine.match("<script>alert(1)</script>");
        assertNull(result);
    }

    @Test
    @DisplayName("Should match multiple attack patterns")
    void testMultiplePatterns() {
        String xssInput = "<img src=x onerror=alert(1)>";
        String sqlInput = "1' OR '1'='1' UNION SELECT username, password FROM users--";
        
        String xssResult = ruleEngine.match(xssInput);
        String sqlResult = ruleEngine.match(sqlInput);
        
        assertNotNull(sqlResult);
        assertEquals("sql-union-select", sqlResult);
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
