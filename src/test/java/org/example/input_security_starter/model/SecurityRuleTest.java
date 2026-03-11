package org.example.input_security_starter.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecurityRuleTest {

    @Test
    @DisplayName("Should create rule with default values")
    void testDefaultValues() {
        SecurityRule rule = new SecurityRule();
        
        assertEquals("high", rule.getLevel());
        assertTrue(rule.isEnabled());
    }

    @Test
    @DisplayName("Should set and get all properties")
    void testSettersAndGetters() {
        SecurityRule rule = new SecurityRule();
        rule.setName("test-rule");
        rule.setPattern("<script>.*</script>");
        rule.setLevel("medium");
        rule.setEnabled(false);
        
        assertEquals("test-rule", rule.getName());
        assertEquals("<script>.*</script>", rule.getPattern());
        assertEquals("medium", rule.getLevel());
        assertFalse(rule.isEnabled());
    }

    @Test
    @DisplayName("Should handle null values with defaults")
    void testNullValues() {
        SecurityRule rule = new SecurityRule();
        rule.setName(null);
        rule.setPattern(null);
        rule.setLevel(null);
        
        assertNull(rule.getName());
        assertNull(rule.getPattern());
        assertEquals("high", rule.getLevel()); // null level defaults to "high"
    }
}
