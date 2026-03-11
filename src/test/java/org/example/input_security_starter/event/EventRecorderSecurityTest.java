package org.example.input_security_starter.event;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EventRecorderSecurityTest {

    private EventRecorder eventRecorder;

    @BeforeEach
    void setUp() {
        eventRecorder = new EventRecorder();
    }

    @Test
    @DisplayName("Should handle newline characters in log content")
    void testNewlineInjection() {
        String maliciousInput = "normal input\n2025-01-01 | FAKE_IP | FAKE_RULE | GET | fake content";
        
        SecurityEvent event = new SecurityEvent("xss-attack", maliciousInput, "/api/test", "GET", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
        assertEquals(maliciousInput, events.get(0).getInputSnippet());
    }

    @Test
    @DisplayName("Should handle carriage return characters")
    void testCarriageReturnInjection() {
        String maliciousInput = "normal input\r\nFAKE_LOG_ENTRY";
        
        SecurityEvent event = new SecurityEvent("sql-injection", maliciousInput, "/api/test", "POST", "10.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should handle tab characters")
    void testTabInjection() {
        String inputWithTabs = "input\twith\ttabs";
        
        SecurityEvent event = new SecurityEvent("command-injection", inputWithTabs, "/api/test", "GET", "192.168.1.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
        assertEquals(inputWithTabs, events.get(0).getInputSnippet());
    }

    @Test
    @DisplayName("Should handle null bytes")
    void testNullByteInjection() {
        String inputWithNull = "input\u0000with\u0000null";
        
        SecurityEvent event = new SecurityEvent("path-traversal", inputWithNull, "/api/test", "GET", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should handle combined injection attempts")
    void testCombinedInjection() {
        String maliciousInput = "normal\r\nFAKE_ENTRY\t\u0000another";
        
        SecurityEvent event = new SecurityEvent("xss-attack", maliciousInput, "/api/test", "GET", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should handle null input snippet")
    void testNullInputSnippet() {
        SecurityEvent event = new SecurityEvent("test-rule", null, "/api/test", "GET", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should handle empty input snippet")
    void testEmptyInputSnippet() {
        SecurityEvent event = new SecurityEvent("test-rule", "", "/api/test", "GET", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should handle very long input")
    void testVeryLongInput() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("a");
        }
        String longInput = sb.toString();
        
        SecurityEvent event = new SecurityEvent("test-rule", longInput, "/api/test", "GET", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
        assertEquals(longInput, events.get(0).getInputSnippet());
    }

    @Test
    @DisplayName("Should handle special characters in rule name")
    void testSpecialCharsInRuleName() {
        SecurityEvent event = new SecurityEvent("rule\nwith\nnewlines", "input", "/api/test", "GET", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should handle special characters in IP address")
    void testSpecialCharsInIpAddress() {
        SecurityEvent event = new SecurityEvent("test-rule", "input", "/api/test", "GET", "192.168.1.1\nFAKE_IP");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should handle special characters in method")
    void testSpecialCharsInMethod() {
        SecurityEvent event = new SecurityEvent("test-rule", "input", "/api/test", "GET\r\nPOST", "127.0.0.1");
        eventRecorder.record(event);
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(1);
        assertEquals(1, events.size());
    }

    @Test
    @DisplayName("Should generate compact log format")
    void testCompactLogFormat() {
        SecurityEvent event = new SecurityEvent.Builder("xss-attack", "<script>alert(1)</script>", "/api/test", "POST")
            .ipAddress("192.168.1.1")
            .ruleLevel("high")
            .build();
        
        eventRecorder.record(event);
        
        Map<String, Object> map = event.toMap();
        assertNotNull(map.get("ts"));
        assertEquals("xss-attack", map.get("rule"));
        assertEquals("high", map.get("level"));
        assertEquals("192.168.1.1", map.get("ip"));
        assertEquals("POST", map.get("method"));
        assertEquals("/api/test", map.get("url"));
        assertEquals("<script>alert(1)</script>", map.get("payload"));
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {
        eventRecorder.shutdown();
    }
}
