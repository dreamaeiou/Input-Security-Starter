package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AttackChainTracker Tests")
class AttackChainTrackerTest {

    private AttackChainTracker tracker;
    private TestAlertHandler alertHandler;

    @BeforeEach
    void setUp() {
        tracker = new AttackChainTracker(100, 5, 20, 2);
        alertHandler = new TestAlertHandler();
        tracker.setAlertHandler(alertHandler);
    }

    @Test
    @DisplayName("Should map rules to expected phases")
    void testRulePhaseMapping() {
        assertEquals(AttackPhase.RECONNAISSANCE, AttackChainTracker.getPhaseForRule("ssrf-attack"));
        assertEquals(AttackPhase.DELIVERY, AttackChainTracker.getPhaseForRule("xss-attack"));
        assertEquals(AttackPhase.EXPLOITATION, AttackChainTracker.getPhaseForRule("command-injection"));
        assertNull(AttackChainTracker.getPhaseForRule("unknown-rule"));
    }

    @Test
    @DisplayName("Should detect complete chain and trigger alert")
    void testCompleteAttackChain() {
        String clientIp = "192.168.1.100";
        String sid = "sess-abc123";
        String expectedSessionId = clientIp + ":" + sid;

        tracker.onSecurityEvent(createSecurityEvent("ssrf-attack", clientIp, sid));
        tracker.onSecurityEvent(createSecurityEvent("sql-injection", clientIp, sid));
        tracker.onSecurityEvent(createSecurityEvent("command-injection", clientIp, sid));

        AttackSession session = tracker.getSession(expectedSessionId);
        assertNotNull(session);
        assertTrue(session.isChainDetected());
        assertTrue(session.getChains().size() >= 2);
        assertEquals(AttackPhase.EXPLOITATION, session.getCurrentPhase());

        assertFalse(alertHandler.getAlerts().isEmpty());
        AttackChainAlert alert = alertHandler.getAlerts().get(0);
        assertEquals(expectedSessionId, alert.getSessionId());
        assertEquals(clientIp, alert.getClientIp());
        assertTrue(alert.getRiskScore() >= 0 && alert.getRiskScore() <= 100);
        assertNotNull(alert.getThreatLevel());
    }

    @Test
    @DisplayName("Should not detect chain for single phase only")
    void testSinglePhaseNoChain() {
        String clientIp = "172.16.0.100";
        String sid = "sess-single";
        String expectedSessionId = clientIp + ":" + sid;

        for (int i = 0; i < 5; i++) {
            tracker.onSecurityEvent(createSecurityEvent("xss-attack", clientIp, sid));
        }

        AttackSession session = tracker.getSession(expectedSessionId);
        assertNotNull(session);
        assertFalse(session.isChainDetected());
        assertEquals(1, session.getTriggeredPhases().size());
        assertEquals(5, session.getEventCount());
    }

    @Test
    @DisplayName("Should include attacker profile context in alert when index is enabled")
    void testAlertContainsAttackerProfileContext() {
        AttackerIndex attackerIndex = new AttackerIndex(100, 7, 10, 1, 10, 60);
        tracker.setAttackerIndex(attackerIndex);

        String clientIp = "203.0.113.9";
        String sid = "sess-profile";
        tracker.onSecurityEvent(createSecurityEvent("ssrf-attack", clientIp, sid));
        tracker.onSecurityEvent(createSecurityEvent("sql-injection", clientIp, sid));
        tracker.onSecurityEvent(createSecurityEvent("command-injection", clientIp, sid));

        assertFalse(alertHandler.getAlerts().isEmpty());
        AttackChainAlert alert = alertHandler.getAlerts().get(0);
        assertNotNull(alert.getAttackerProfile());
        assertTrue(alert.getAttackerProfile().containsKey("total_attack_count"));
        assertNotNull(alert.getThreatLevel());
    }

    @Test
    @DisplayName("Should keep phase ordering behavior")
    void testPhaseOrder() {
        assertTrue(AttackPhase.RECONNAISSANCE.isBefore(AttackPhase.DELIVERY));
        assertTrue(AttackPhase.DELIVERY.isBefore(AttackPhase.EXPLOITATION));
        assertTrue(AttackPhase.EXPLOITATION.isAfter(AttackPhase.DELIVERY));
        assertEquals(1, AttackPhase.DELIVERY.distance(AttackPhase.RECONNAISSANCE));
    }

    private SecurityEvent createSecurityEvent(String ruleName, String clientIp, String sessionId) {
        return new SecurityEvent.Builder(ruleName, "test-payload", "/api/test", "GET")
            .ipAddress(clientIp)
            .sessionId(sessionId)
            .originalInput("malicious-input")
            .normalizedInput("malicious-input")
            .inputSource("parameter")
            .parameterName("q")
            .ruleLevel("high")
            .build();
    }

    private static class TestAlertHandler implements AttackChainTracker.AlertHandler {
        private final List<AttackChainAlert> alerts = new CopyOnWriteArrayList<AttackChainAlert>();

        @Override
        public void onAlert(AttackChainAlert alert) {
            alerts.add(alert);
        }

        List<AttackChainAlert> getAlerts() {
            return new ArrayList<AttackChainAlert>(alerts);
        }
    }
}
