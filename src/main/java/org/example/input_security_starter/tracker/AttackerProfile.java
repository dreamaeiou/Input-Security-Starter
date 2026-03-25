package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Per-IP global attacker profile for cross-session tracking.
 */
public class AttackerProfile {

    private final String ip;
    private volatile Integer asn;
    private volatile String country;
    private volatile String isp;
    private volatile long firstSeenTimestamp;
    private volatile long lastSeenTimestamp;
    private volatile long totalAttackCount;
    private final Map<String, Integer> attackTypeCounts;
    private final Map<String, Integer> targetUrlCounts;
    private final Deque<String> attackPhaseHistory;
    private volatile double lastRiskScore;
    private volatile String threatLevel;
    private volatile String tag;
    private final Deque<String> recentSessions;

    public AttackerProfile(String ip, long nowTs) {
        this.ip = ip;
        this.firstSeenTimestamp = nowTs;
        this.lastSeenTimestamp = nowTs;
        this.totalAttackCount = 0L;
        this.attackTypeCounts = new HashMap<String, Integer>();
        this.targetUrlCounts = new HashMap<String, Integer>();
        this.attackPhaseHistory = new ArrayDeque<String>();
        this.lastRiskScore = 0D;
        this.threatLevel = "low";
        this.tag = "auto";
        this.recentSessions = new ArrayDeque<String>();
    }

    public synchronized void recordEvent(
        SecurityEvent event,
        AttackPhase phase,
        double riskScore,
        String threatLevel,
        int maxRecentSessions
    ) {
        long ts = event != null && event.getTimestamp() != null
            ? event.getTimestamp().getTime()
            : System.currentTimeMillis();

        if (totalAttackCount == 0L) {
            firstSeenTimestamp = ts;
        }
        lastSeenTimestamp = ts;
        totalAttackCount++;

        if (event != null) {
            if (event.getRuleName() != null && !event.getRuleName().isEmpty()) {
                attackTypeCounts.put(event.getRuleName(), attackTypeCounts.getOrDefault(event.getRuleName(), 0) + 1);
            }
            if (event.getUrl() != null && !event.getUrl().isEmpty()) {
                targetUrlCounts.put(event.getUrl(), targetUrlCounts.getOrDefault(event.getUrl(), 0) + 1);
            }
            if (event.getSessionId() != null && !event.getSessionId().isEmpty()) {
                appendRecentSession(event.getSessionId(), maxRecentSessions);
            }
        }

        if (phase != null) {
            appendPhase(phase.getId(), 50);
        }

        this.lastRiskScore = riskScore;
        if (threatLevel != null && !threatLevel.trim().isEmpty()) {
            this.threatLevel = threatLevel.trim().toLowerCase();
        }
    }

    public synchronized void setNetworkInfo(Integer asn, String country, String isp) {
        if (asn != null && asn > 0) {
            this.asn = asn;
        }
        if (country != null && !country.trim().isEmpty()) {
            this.country = country.trim().toUpperCase();
        }
        if (isp != null && !isp.trim().isEmpty()) {
            this.isp = isp.trim();
        }
    }

    private void appendPhase(String phaseId, int maxPhaseHistory) {
        if (phaseId == null || phaseId.isEmpty()) {
            return;
        }
        String last = attackPhaseHistory.peekLast();
        if (phaseId.equals(last)) {
            return;
        }
        attackPhaseHistory.addLast(phaseId);
        while (attackPhaseHistory.size() > maxPhaseHistory) {
            attackPhaseHistory.pollFirst();
        }
    }

    private void appendRecentSession(String sessionId, int maxRecentSessions) {
        String last = recentSessions.peekLast();
        if (sessionId.equals(last)) {
            return;
        }
        recentSessions.addLast(sessionId);
        int safeMax = Math.max(1, maxRecentSessions);
        while (recentSessions.size() > safeMax) {
            recentSessions.pollFirst();
        }
    }

    public synchronized List<String> getTopAttackTypes(int limit) {
        List<Map.Entry<String, Integer>> entries = new ArrayList<Map.Entry<String, Integer>>(attackTypeCounts.entrySet());
        entries.sort(new Comparator<Map.Entry<String, Integer>>() {
            @Override
            public int compare(Map.Entry<String, Integer> a, Map.Entry<String, Integer> b) {
                return Integer.compare(b.getValue(), a.getValue());
            }
        });

        int max = Math.min(Math.max(0, limit), entries.size());
        List<String> top = new ArrayList<String>(max);
        for (int i = 0; i < max; i++) {
            top.add(entries.get(i).getKey());
        }
        return top;
    }

    public synchronized Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("ip", ip);
        if (asn != null) {
            map.put("asn", asn);
        }
        if (country != null) {
            map.put("country", country);
        }
        if (isp != null) {
            map.put("isp", isp);
        }
        map.put("first_seen_ts", firstSeenTimestamp);
        map.put("last_seen_ts", lastSeenTimestamp);
        map.put("total_attack_count", totalAttackCount);
        map.put("attack_type_counts", new HashMap<String, Integer>(attackTypeCounts));
        map.put("target_url_counts", new HashMap<String, Integer>(targetUrlCounts));
        map.put("attack_phase_history", new ArrayList<String>(attackPhaseHistory));
        map.put("last_risk_score", lastRiskScore);
        map.put("threat_level", threatLevel);
        map.put("tag", tag);
        map.put("recent_sessions", new ArrayList<String>(recentSessions));
        return map;
    }

    public String getIp() { return ip; }
    public Integer getAsn() { return asn; }
    public String getCountry() { return country; }
    public String getIsp() { return isp; }
    public long getFirstSeenTimestamp() { return firstSeenTimestamp; }
    public long getLastSeenTimestamp() { return lastSeenTimestamp; }
    public long getTotalAttackCount() { return totalAttackCount; }
    public synchronized Map<String, Integer> getAttackTypeCounts() { return Collections.unmodifiableMap(new HashMap<String, Integer>(attackTypeCounts)); }
    public synchronized Map<String, Integer> getTargetUrlCounts() { return Collections.unmodifiableMap(new HashMap<String, Integer>(targetUrlCounts)); }
    public synchronized List<String> getAttackPhaseHistory() { return Collections.unmodifiableList(new ArrayList<String>(attackPhaseHistory)); }
    public double getLastRiskScore() { return lastRiskScore; }
    public String getThreatLevel() { return threatLevel; }
    public String getTag() { return tag; }
    public synchronized List<String> getRecentSessions() { return Collections.unmodifiableList(new ArrayList<String>(recentSessions)); }

    public void setTag(String tag) {
        if (tag != null && !tag.trim().isEmpty()) {
            this.tag = tag.trim();
        }
    }
}
