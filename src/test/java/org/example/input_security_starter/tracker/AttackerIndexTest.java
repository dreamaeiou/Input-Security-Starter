package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AttackerIndex Tests")
class AttackerIndexTest {

    @Test
    @DisplayName("Should track profile across sessions for same IP")
    void shouldTrackAcrossSessions() {
        AttackerIndex index = new AttackerIndex(100, 7, 10, 1, 10, 60);

        index.recordGlobalProfile(event("10.0.0.1", "s-1", "xss-attack", "/a"), AttackPhase.DELIVERY, 40, "medium");
        index.recordGlobalProfile(event("10.0.0.1", "s-2", "sql-injection", "/b"), AttackPhase.DELIVERY, 65, "high");

        AttackerProfile profile = index.getProfile("10.0.0.1");
        assertNotNull(profile);
        assertEquals(2L, profile.getTotalAttackCount());
        assertEquals(2, profile.getRecentSessions().size());
        assertTrue(profile.getAttackTypeCounts().containsKey("xss-attack"));
        assertTrue(profile.getAttackTypeCounts().containsKey("sql-injection"));
    }

    @Test
    @DisplayName("Should find related attackers by ASN and attack type")
    void shouldFindRelatedAttackers() {
        AttackerIndex index = new AttackerIndex(100, 7, 10, 1, 10, 60);

        index.recordGlobalProfile(event("10.0.0.1", "s-1", "sql-injection", "/a"), AttackPhase.DELIVERY, 60, "high");
        index.recordGlobalProfile(event("10.0.0.2", "s-2", "sql-injection", "/b"), AttackPhase.DELIVERY, 55, "medium");
        index.recordGlobalProfile(event("10.0.0.3", "s-3", "xss-attack", "/c"), AttackPhase.DELIVERY, 30, "low");

        AttackerProfile p1 = index.getProfile("10.0.0.1");
        AttackerProfile p2 = index.getProfile("10.0.0.2");
        assertNotNull(p1);
        assertNotNull(p2);
        p1.setNetworkInfo(64512, "US", "TestISP");
        p2.setNetworkInfo(64512, "US", "TestISP");

        List<AttackerIndex.RelatedAttacker> related = index.findRelatedAttackers("10.0.0.1", 5);
        assertFalse(related.isEmpty());

        Map<String, Object> first = related.get(0).toMap();
        assertTrue(first.containsKey("ip"));
        assertTrue(first.containsKey("similarity"));
        assertTrue(first.containsKey("reasons"));
    }

    @Test
    @DisplayName("Should evict when profiles exceed max size")
    void shouldEvictOverflowProfiles() {
        AttackerIndex index = new AttackerIndex(2, 7, 1, 1, 10, 60);

        index.recordGlobalProfile(event("10.0.0.1", "s-1", "xss-attack", "/a"), AttackPhase.DELIVERY, 30, "low");
        index.recordGlobalProfile(event("10.0.0.2", "s-2", "sql-injection", "/b"), AttackPhase.DELIVERY, 50, "medium");
        index.recordGlobalProfile(event("10.0.0.3", "s-3", "command-injection", "/c"), AttackPhase.EXPLOITATION, 80, "high");

        assertTrue(index.getProfileCount() <= 2);
    }

    private SecurityEvent event(String ip, String sid, String rule, String url) {
        return new SecurityEvent.Builder(rule, "payload", url, "GET")
            .ipAddress(ip)
            .sessionId(sid)
            .originalInput("payload")
            .normalizedInput("payload")
            .inputSource("parameter")
            .parameterName("q")
            .build();
    }
}
