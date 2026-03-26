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

    @Test
    @DisplayName("Low-confidence event should not advance phase progression")
    void testLowConfidenceEventDoesNotAdvanceChain() {
        String clientIp = "198.51.100.10";
        String sid = "sess-low-confidence";
        String expectedSessionId = clientIp + ":" + sid;

        tracker.onSecurityEvent(createSecurityEvent("ssrf-attack", clientIp, sid, 0.45d));
        tracker.onSecurityEvent(createSecurityEvent("sql-injection", clientIp, sid, 0.95d));

        AttackSession session = tracker.getSession(expectedSessionId);
        assertNotNull(session);
        assertFalse(session.isChainDetected(), "low-confidence reconnaissance should not advance chain");
        assertEquals(1, session.getTriggeredPhases().size(), "only delivery phase should be counted");
        assertEquals(2, session.getEventCount(), "all events should still be recorded");
        assertTrue(alertHandler.getAlerts().isEmpty(), "no alert expected");
    }

    @Test
    @DisplayName("Chain confidence should reduce final risk score")
    void testChainConfidenceReducesRiskScore() {
        AttackChainTracker localTracker = new AttackChainTracker(100, 5, 20, 3);
        TestAlertHandler localAlertHandler = new TestAlertHandler();
        localTracker.setAlertHandler(localAlertHandler);

        String highIp = "203.0.113.50";
        String lowIp = "203.0.113.60";
        String sid = "sess-risk";

        localTracker.onSecurityEvent(createSecurityEvent("ssrf-attack", highIp, sid, 0.95d));
        localTracker.onSecurityEvent(createSecurityEvent("sql-injection", highIp, sid, 0.95d));
        localTracker.onSecurityEvent(createSecurityEvent("command-injection", highIp, sid, 0.95d));

        localTracker.onSecurityEvent(createSecurityEvent("ssrf-attack", lowIp, sid, 0.95d));
        localTracker.onSecurityEvent(createSecurityEvent("sql-injection", lowIp, sid, 0.95d));
        localTracker.onSecurityEvent(createSecurityEvent("command-injection", lowIp, sid, 0.60d));

        AttackChainAlert highAlert = findAlertByIp(localAlertHandler, highIp);
        AttackChainAlert lowAlert = findAlertByIp(localAlertHandler, lowIp);

        assertNotNull(highAlert);
        assertNotNull(lowAlert);
        assertTrue(highAlert.getRiskScore() >= lowAlert.getRiskScore(),
            "lower chain confidence should not produce a higher final risk score");
        assertTrue(highAlert.getChainConfidence() > lowAlert.getChainConfidence(),
            "chain confidence should be reflected in alert payload");
    }

    private SecurityEvent createSecurityEvent(String ruleName, String clientIp, String sessionId) {
        return createSecurityEvent(ruleName, clientIp, sessionId, 1.0d);
    }

    private SecurityEvent createSecurityEvent(String ruleName, String clientIp, String sessionId, double confidence) {
        return new SecurityEvent.Builder(ruleName, "test-payload", "/api/test", "GET")
            .ipAddress(clientIp)
            .sessionId(sessionId)
            .originalInput("malicious-input")
            .normalizedInput("malicious-input")
            .inputSource("parameter")
            .parameterName("q")
            .ruleLevel("high")
            .eventConfidence(confidence)
            .build();
    }

    private AttackChainAlert findAlertByIp(TestAlertHandler handler, String ip) {
        for (AttackChainAlert alert : handler.getAlerts()) {
            if (ip.equals(alert.getClientIp())) {
                return alert;
            }
        }
        return null;
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
