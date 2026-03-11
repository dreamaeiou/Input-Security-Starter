package org.example.input_security_starter.event;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SecurityEventTest {

    @Test
    @DisplayName("Should create event with all fields")
    void testCreateEventWithAllFields() {
        SecurityEvent event = new SecurityEvent("xss-attack", "<script>alert(1)</script>", "/api/test", "POST", "192.168.1.1");
        
        assertEquals("xss-attack", event.getRuleName());
        assertEquals("<script>alert(1)</script>", event.getInputSnippet());
        assertEquals("/api/test", event.getUrl());
        assertEquals("POST", event.getMethod());
        assertEquals("192.168.1.1", event.getIpAddress());
        assertNotNull(event.getTimestamp());
    }

    @Test
    @DisplayName("Should create event without IP address")
    void testCreateEventWithoutIp() {
        SecurityEvent event = new SecurityEvent("sql-injection", "UNION SELECT", "/api/users", "GET");
        
        assertEquals("sql-injection", event.getRuleName());
        assertEquals("UNION SELECT", event.getInputSnippet());
        assertEquals("/api/users", event.getUrl());
        assertEquals("GET", event.getMethod());
        assertNull(event.getIpAddress());
    }

    @Test
    @DisplayName("Should set IP address")
    void testSetIpAddress() {
        SecurityEvent event = new SecurityEvent("test", "input", "/api/test", "GET");
        event.setIpAddress("10.0.0.1");
        
        assertEquals("10.0.0.1", event.getIpAddress());
    }

    @Test
    @DisplayName("Should format timestamp")
    void testFormattedTimestamp() {
        SecurityEvent event = new SecurityEvent("test", "input", "/api/test", "GET");
        
        String formatted = event.getFormattedTimestamp();
        assertNotNull(formatted);
        assertTrue(formatted.matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}"));
    }

    @Test
    @DisplayName("Should generate map with required fields")
    void testToMapBasic() {
        SecurityEvent event = new SecurityEvent("xss-attack", "<script>alert(1)</script>", "/api/test", "POST", "192.168.1.1");
        
        Map<String, Object> map = event.toMap();
        
        assertNotNull(map.get("ts"));
        assertEquals("xss-attack", map.get("rule"));
        assertEquals("192.168.1.1", map.get("ip"));
        assertEquals("POST", map.get("method"));
        assertEquals("/api/test", map.get("url"));
        assertEquals("<script>alert(1)</script>", map.get("payload"));
    }

    @Test
    @DisplayName("Should include optional fields when present")
    void testToMapWithOptionalFields() {
        SecurityEvent event = new SecurityEvent.Builder("sql-injection", "SELECT * FROM users", "/api/users", "GET")
            .ipAddress("10.0.0.1")
            .parameterName("id")
            .sessionId("sess123")
            .ruleLevel("high")
            .inputSource("query")
            .build();
        
        Map<String, Object> map = event.toMap();
        
        assertEquals("high", map.get("level"));
        assertEquals("sess123", map.get("sid"));
        assertEquals("id", map.get("param"));
        assertEquals("query", map.get("source"));
    }

    @Test
    @DisplayName("Should truncate long payload")
    void testPayloadTruncation() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 300; i++) {
            sb.append("a");
        }
        String longInput = sb.toString();
        
        SecurityEvent event = new SecurityEvent("test", longInput, "/api/test", "GET");
        Map<String, Object> map = event.toMap();
        
        String payload = (String) map.get("payload");
        assertTrue(payload.length() <= 203);
        assertTrue(payload.endsWith("..."));
    }

    @Test
    @DisplayName("Should include normalized input when different")
    void testNormalizedInputIncluded() {
        SecurityEvent event = new SecurityEvent.Builder("xss-attack", "%3Cscript%3E", "/api/test", "GET")
            .normalizedInput("<script>")
            .build();
        
        Map<String, Object> map = event.toMap();
        
        assertEquals("%3Cscript%3E", map.get("payload"));
        assertEquals("<script>", map.get("normalized"));
    }

    @Test
    @DisplayName("Should not include normalized input when same")
    void testNormalizedInputExcluded() {
        SecurityEvent event = new SecurityEvent.Builder("xss-attack", "<script>", "/api/test", "GET")
            .normalizedInput("<script>")
            .build();
        
        Map<String, Object> map = event.toMap();
        
        assertNull(map.get("normalized"));
    }

    @Test
    @DisplayName("Should handle null input snippet")
    void testNullInputSnippet() {
        SecurityEvent event = new SecurityEvent("test-rule", null, "/api/test", "GET");
        Map<String, Object> map = event.toMap();
        
        assertNull(map.get("payload"));
    }
}
