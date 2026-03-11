package org.example.input_security_starter.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class InputSecurityPropertiesTest {

    private InputSecurityProperties properties;

    @BeforeEach
    void setUp() {
        properties = new InputSecurityProperties();
    }

    @Test
    @DisplayName("Should have default values")
    void testDefaultValues() {
        assertTrue(properties.isEnabled());
        assertEquals(InputSecurityProperties.Mode.MONITOR, properties.getMode());
    }

    @Test
    @DisplayName("Should set enabled")
    void testSetEnabled() {
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
    }

    @Test
    @DisplayName("Should set mode")
    void testSetMode() {
        properties.setMode(InputSecurityProperties.Mode.BLOCK);
        assertEquals(InputSecurityProperties.Mode.BLOCK, properties.getMode());
    }

    @Test
    @DisplayName("Should provide default rules when empty")
    void testDefaultRules() {
        List<org.example.input_security_starter.model.SecurityRule> rules = properties.getRules();
        
        assertFalse(rules.isEmpty());
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("xss-attack")));
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("sql-injection")));
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("code-execution")));
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("command-injection")));
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("ssrf-attack")));
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("path-traversal")));
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("ldap-injection")));
        assertTrue(rules.stream().anyMatch(r -> r.getName().equals("xxe-injection")));
    }

    @Test
    @DisplayName("Should return copy of rules")
    void testRulesCopy() {
        List<org.example.input_security_starter.model.SecurityRule> rules1 = properties.getRules();
        List<org.example.input_security_starter.model.SecurityRule> rules2 = properties.getRules();
        
        assertNotSame(rules1, rules2);
    }

    @Test
    @DisplayName("Should have correct mode values")
    void testModeValues() {
        assertEquals(2, InputSecurityProperties.Mode.values().length);
        assertEquals("MONITOR", InputSecurityProperties.Mode.MONITOR.name());
        assertEquals("BLOCK", InputSecurityProperties.Mode.BLOCK.name());
    }

    @Test
    @DisplayName("Default rules should be enabled")
    void testDefaultRulesEnabled() {
        List<org.example.input_security_starter.model.SecurityRule> rules = properties.getRules();
        
        for (org.example.input_security_starter.model.SecurityRule rule : rules) {
            assertTrue(rule.isEnabled(), "Rule " + rule.getName() + " should be enabled by default");
        }
    }

    @Test
    @DisplayName("Default rules should have valid levels")
    void testDefaultRulesLevels() {
        List<org.example.input_security_starter.model.SecurityRule> rules = properties.getRules();
        
        for (org.example.input_security_starter.model.SecurityRule rule : rules) {
            assertTrue(
                rule.getLevel().equals("high") || 
                rule.getLevel().equals("medium") || 
                rule.getLevel().equals("low"),
                "Rule " + rule.getName() + " has invalid level: " + rule.getLevel()
            );
        }
    }
}
