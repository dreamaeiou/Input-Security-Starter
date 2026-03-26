package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Attack chain state machine with optional global attacker index.
 */
public class AttackChainTracker {

    private static final Logger log = LoggerFactory.getLogger(AttackChainTracker.class);

    private static final int DEFAULT_RISK_THRESHOLD = 80;
    private static final int DEFAULT_MAX_RELATED_ATTACKERS = 10;
    private static final double DEFAULT_EVENT_CONFIDENCE_THRESHOLD = 0.60d;

    /** Rule name -> kill-chain phase */
    private static final Map<String, AttackPhase> RULE_PHASE_MAP;

    static {
        Map<String, AttackPhase> map = new HashMap<String, AttackPhase>();
        map.put("ssrf-attack", AttackPhase.RECONNAISSANCE);
        map.put("path-traversal", AttackPhase.RECONNAISSANCE);
        map.put("ldap-injection", AttackPhase.RECONNAISSANCE);

        map.put("xss-attack", AttackPhase.DELIVERY);
        map.put("sql-injection", AttackPhase.DELIVERY);
        map.put("xxe-injection", AttackPhase.DELIVERY);
        map.put("nosql-injection", AttackPhase.DELIVERY);
        map.put("template-injection", AttackPhase.DELIVERY);

        map.put("command-injection", AttackPhase.EXPLOITATION);
        map.put("code-execution", AttackPhase.EXPLOITATION);
        map.put("deserialization-attack", AttackPhase.EXPLOITATION);

        map.put("installation-attack", AttackPhase.INSTALLATION);
        map.put("c2-communication", AttackPhase.COMMAND_CONTROL);
        map.put("actions-on-objectives", AttackPhase.ACTIONS);
        RULE_PHASE_MAP = Collections.unmodifiableMap(map);
    }

    private final ConcurrentHashMap<String, AttackSession> sessionPool;
    private final int maxSessions;
    private final long sessionTimeoutMs;
    private final int maxEventsPerSession;
    private final int minPhasesForChain;
    private final int riskScoreThreshold;

    private volatile double eventConfidenceThreshold = DEFAULT_EVENT_CONFIDENCE_THRESHOLD;
    private int maxRelatedAttackers = DEFAULT_MAX_RELATED_ATTACKERS;

    private AlertHandler alertHandler;
    private final ScheduledExecutorService scheduler;
    private volatile AttackerIndex attackerIndex;

    public static AttackPhase getPhaseForRule(String ruleName) {
        return RULE_PHASE_MAP.get(ruleName);
    }

    public AttackChainTracker(
        int maxSessions,
        int sessionTimeoutMinutes,
        int maxEventsPerSession,
        int minPhasesForChain
    ) {
        this(maxSessions, sessionTimeoutMinutes, maxEventsPerSession, minPhasesForChain, DEFAULT_RISK_THRESHOLD);
    }

    public AttackChainTracker(
        int maxSessions,
        int sessionTimeoutMinutes,
        int maxEventsPerSession,
        int minPhasesForChain,
        int riskScoreThreshold
    ) {
        this.sessionPool = new ConcurrentHashMap<String, AttackSession>();
        this.maxSessions = maxSessions;
        this.sessionTimeoutMs = sessionTimeoutMinutes * 60 * 1000L;
        this.maxEventsPerSession = maxEventsPerSession;
        this.minPhasesForChain = minPhasesForChain;
        this.riskScoreThreshold = Math.max(1, Math.min(100, riskScoreThreshold));

        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "attack-chain-cleaner");
            t.setDaemon(true);
            return t;
        });
        this.scheduler.scheduleAtFixedRate(this::cleanExpiredSessions, 1, 1, TimeUnit.MINUTES);

        log.info(
            "AttackChainTracker initialized: maxSessions={}, timeout={}min, riskThreshold={}, eventConfidenceThreshold={}",
            maxSessions, sessionTimeoutMinutes, this.riskScoreThreshold, this.eventConfidenceThreshold
        );
    }

    /**
     * Main event entrypoint.
     */
    public void onSecurityEvent(SecurityEvent event) {
        String ruleName = event.getRuleName();
        if (ruleName == null) {
            return;
        }

        AttackPhase phase = RULE_PHASE_MAP.get(ruleName);
        if (phase == null) {
            return;
        }

        String sessionId = buildSessionId(event);
        String clientIp = event.getIpAddress();
        if (clientIp == null || clientIp.trim().isEmpty()) {
            clientIp = "unknown";
        }
        AttackSession session = getOrCreateSession(sessionId, clientIp);

        double confidence = normalizeEventConfidence(event.getEventConfidence());
        boolean contributesToChain = confidence >= eventConfidenceThreshold;

        session.recordEvent(event, phase, contributesToChain);
        if (contributesToChain) {
            detectAttackChain(session, phase, ruleName);
        } else {
            log.debug("Low-confidence event excluded from phase progression: sessionId={}, rule={}, confidence={}",
                sessionId, ruleName, confidence);
        }

        RiskComputation risk = calculateRiskScore(session);
        String threatLevel = resolveThreatLevel(risk.finalScore);
        recordAttackerProfile(event, phase, risk.finalScore, threatLevel);

        checkAndAlert(session, event, risk, threatLevel);
    }

    private void recordAttackerProfile(SecurityEvent event, AttackPhase phase, int riskScore, String threatLevel) {
        AttackerIndex index = this.attackerIndex;
        if (index == null) {
            return;
        }
        try {
            index.recordGlobalProfile(event, phase, riskScore, threatLevel);
        } catch (Exception e) {
            log.debug("Failed to update attacker profile: {}", e.getMessage());
        }
    }

    private String buildSessionId(SecurityEvent event) {
        String ip = event.getIpAddress();
        if (ip == null || ip.trim().isEmpty()) {
            ip = "unknown";
        }
        String httpSessionId = event.getSessionId();

        if (httpSessionId != null && !httpSessionId.isEmpty()) {
            return ip + ":" + httpSessionId;
        }
        return ip;
    }

    private AttackSession getOrCreateSession(String sessionId, String clientIp) {
        return sessionPool.computeIfAbsent(sessionId, id -> new AttackSession(id, clientIp, maxEventsPerSession));
    }

    private void detectAttackChain(AttackSession session, AttackPhase newPhase, String ruleName) {
        EnumSet<AttackPhase> phases = session.getTriggeredPhases();
        if (phases.size() < minPhasesForChain) {
            return;
        }

        long newTimestamp = System.currentTimeMillis();
        for (AttackPhase existingPhase : phases) {
            if (newPhase.isAfter(existingPhase)) {
                long existingTimestamp = getLastTimestampForPhase(session, existingPhase);

                AttackSession.AttackChain chain = new AttackSession.AttackChain(
                    existingPhase,
                    newPhase,
                    getLastRuleForPhase(session, existingPhase),
                    ruleName,
                    existingTimestamp,
                    newTimestamp
                );

                boolean isValid = chain.validate(30);
                if (isValid && session.addChain(chain)) {
                    log.info(
                        "Attack chain detected and verified: sessionId={}, chain={}, note={}",
                        session.getSessionId(),
                        chain.getDescription(),
                        chain.getVerificationNote()
                    );
                } else if (!isValid) {
                    log.debug("Attack chain rejected: sessionId={}, reason={}",
                        session.getSessionId(), chain.getVerificationNote());
                }
            }
        }
    }

    private String getLastRuleForPhase(AttackSession session, AttackPhase phase) {
        List<SecurityEvent> events = session.getEvents();
        for (int i = events.size() - 1; i >= 0; i--) {
            SecurityEvent event = events.get(i);
            AttackPhase eventPhase = RULE_PHASE_MAP.get(event.getRuleName());
            if (eventPhase == phase && isEventEligibleForChain(event)) {
                return event.getRuleName();
            }
        }
        return "unknown";
    }

    private long getLastTimestampForPhase(AttackSession session, AttackPhase phase) {
        List<SecurityEvent> events = session.getEvents();
        for (int i = events.size() - 1; i >= 0; i--) {
            SecurityEvent event = events.get(i);
            AttackPhase eventPhase = RULE_PHASE_MAP.get(event.getRuleName());
            if (eventPhase == phase && event.getTimestamp() != null && isEventEligibleForChain(event)) {
                return event.getTimestamp().getTime();
            }
        }
        return 0;
    }

    private RiskComputation calculateRiskScore(AttackSession session) {
        int rawScore = 0;

        AttackPhase current = session.getCurrentPhase();
        if (current != null) {
            rawScore = Math.max(rawScore, current.getBaseScore());
        }

        int phaseCount = session.getTriggeredPhases().size();
        rawScore += Math.min(phaseCount * 6, 18);

        int chainCount = session.getChains().size();
        rawScore += Math.min(chainCount * 8, 20);

        int eventCount = session.getChainEventCount();
        if (eventCount > 15) {
            rawScore += 15;
        } else if (eventCount > 8) {
            rawScore += 10;
        } else if (eventCount > 4) {
            rawScore += 6;
        } else if (eventCount > 1) {
            rawScore += 3;
        }

        EnumSet<AttackPhase> phases = session.getTriggeredPhases();
        if (phases.contains(AttackPhase.EXPLOITATION)) {
            rawScore += 10;
        }
        if (phases.contains(AttackPhase.INSTALLATION)
            || phases.contains(AttackPhase.COMMAND_CONTROL)
            || phases.contains(AttackPhase.ACTIONS)) {
            rawScore += 12;
        }

        rawScore = clampInt(rawScore, 0, 100);

        double chainConfidence = calculateChainConfidence(session);
        int finalScore = clampInt((int) Math.round(rawScore * chainConfidence), 0, 100);
        return new RiskComputation(rawScore, chainConfidence, finalScore);
    }

    private double calculateChainConfidence(AttackSession session) {
        List<SecurityEvent> events = session.getEvents();
        double sumLog = 0.0d;
        int count = 0;
        for (SecurityEvent event : events) {
            AttackPhase phase = RULE_PHASE_MAP.get(event.getRuleName());
            if (phase == null) {
                continue;
            }
            double confidence = normalizeEventConfidence(event.getEventConfidence());
            if (confidence >= eventConfidenceThreshold) {
                sumLog += Math.log(Math.max(0.01d, confidence));
                count++;
            }
        }

        if (count <= 0) {
            return 1.0d;
        }

        double geometricMean = Math.exp(sumLog / count);
        return clampDouble(geometricMean, 0.05d, 1.0d);
    }

    private boolean isEventEligibleForChain(SecurityEvent event) {
        if (event == null) {
            return false;
        }
        return normalizeEventConfidence(event.getEventConfidence()) >= eventConfidenceThreshold;
    }

    private double normalizeEventConfidence(double confidence) {
        if (Double.isNaN(confidence) || Double.isInfinite(confidence)) {
            return 1.0d;
        }
        return clampDouble(confidence, 0.0d, 1.0d);
    }

    private String resolveThreatLevel(int riskScore) {
        if (riskScore >= 85) {
            return "critical";
        }
        if (riskScore >= 70) {
            return "high";
        }
        if (riskScore >= 45) {
            return "medium";
        }
        return "low";
    }

    private void checkAndAlert(AttackSession session, SecurityEvent event, RiskComputation risk, String threatLevel) {
        if (alertHandler == null || session.isAlertSent()) {
            return;
        }

        boolean chainDetected = session.isChainDetected();
        boolean riskExceeded = risk.finalScore >= riskScoreThreshold;
        if (!chainDetected && !riskExceeded) {
            return;
        }

        String reason = chainDetected ? "attack_chain_detected" : "risk_threshold_exceeded";
        AttackChainAlert alert = buildAlert(session, event, reason, risk, threatLevel);
        alertHandler.onAlert(alert);
        session.markAlertSent();
    }

    private AttackChainAlert buildAlert(
        AttackSession session,
        SecurityEvent event,
        String reason,
        RiskComputation risk,
        String threatLevel
    ) {
        AttackChainAlert alert = new AttackChainAlert();
        alert.setAlertType(reason);
        alert.setSessionId(session.getSessionId());
        alert.setClientIp(session.getClientIp());
        alert.setCurrentPhase(session.getCurrentPhase());
        alert.setTriggeredPhases(session.getTriggeredPhases());
        alert.setChains(session.getChains());
        alert.setEventCount(session.getEventCount());
        alert.setDuration(session.getDuration());
        alert.setEvents(buildEventSummaries(session));
        alert.setRiskScore(risk.finalScore);
        alert.setChainConfidence(risk.chainConfidence);
        alert.setThreatLevel(threatLevel);

        AttackerIndex index = this.attackerIndex;
        if (index != null && session.getClientIp() != null) {
            AttackerProfile profile = index.getProfile(session.getClientIp());
            if (profile != null) {
                alert.setAttackerProfile(profile.toMap());
            }

            List<AttackerIndex.RelatedAttacker> related = index.findRelatedAttackers(
                session.getClientIp(), maxRelatedAttackers
            );
            if (!related.isEmpty()) {
                List<Map<String, Object>> relatedMaps = new ArrayList<Map<String, Object>>(related.size());
                for (AttackerIndex.RelatedAttacker r : related) {
                    relatedMaps.add(r.toMap());
                }
                alert.setRelatedAttackers(relatedMaps);
            }
        }
        return alert;
    }

    private List<Map<String, Object>> buildEventSummaries(AttackSession session) {
        List<Map<String, Object>> summaries = new ArrayList<Map<String, Object>>();
        for (SecurityEvent evt : session.getEvents()) {
            Map<String, Object> summary = new HashMap<String, Object>();
            summary.put("ts", evt.getTimestamp().getTime());
            summary.put("rule", evt.getRuleName());
            summary.put("url", evt.getUrl());
            summary.put("ip", evt.getIpAddress());
            summary.put("event_confidence", roundTo3(normalizeEventConfidence(evt.getEventConfidence())));

            String payload = evt.getOriginalInput();
            if (payload != null && payload.length() > 100) {
                summary.put("payload_preview", payload.substring(0, 100) + "...");
            } else {
                summary.put("payload_preview", payload);
            }

            AttackPhase phase = RULE_PHASE_MAP.get(evt.getRuleName());
            if (phase != null) {
                summary.put("phase", phase.getId());
            }

            if (evt.getMethod() != null) {
                summary.put("method", evt.getMethod());
            }

            if (evt.getUserAgent() != null) {
                summary.put("user_agent", evt.getUserAgent());
            }

            if (evt.getStatusCode() != null) {
                summary.put("status_code", evt.getStatusCode());
            }

            if (evt.getParameterName() != null) {
                summary.put("param", evt.getParameterName());
            }

            if (evt.getInputSource() != null) {
                summary.put("source", evt.getInputSource());
            }

            summaries.add(summary);
        }
        return summaries;
    }

    private void cleanExpiredSessions() {
        int removed = 0;
        for (Map.Entry<String, AttackSession> entry : sessionPool.entrySet()) {
            if (entry.getValue().isExpired(sessionTimeoutMs)) {
                sessionPool.remove(entry.getKey());
                removed++;
            }
        }

        while (sessionPool.size() > maxSessions) {
            String oldestKey = findOldestSession();
            if (oldestKey != null) {
                sessionPool.remove(oldestKey);
                removed++;
            } else {
                break;
            }
        }

        if (removed > 0) {
            log.debug("Cleaned {} expired sessions, current pool size: {}", removed, sessionPool.size());
        }
    }

    private String findOldestSession() {
        String oldestKey = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<String, AttackSession> entry : sessionPool.entrySet()) {
            if (entry.getValue().getFirstSeen() < oldestTime) {
                oldestTime = entry.getValue().getFirstSeen();
                oldestKey = entry.getKey();
            }
        }
        return oldestKey;
    }

    public int getSessionPoolSize() {
        return sessionPool.size();
    }

    public AttackSession getSession(String sessionId) {
        return sessionPool.get(sessionId);
    }

    public void setAlertHandler(AlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    public void setAttackerIndex(AttackerIndex attackerIndex) {
        this.attackerIndex = attackerIndex;
    }

    public AttackerIndex getAttackerIndex() {
        return attackerIndex;
    }

    public void setMaxRelatedAttackers(int maxRelatedAttackers) {
        this.maxRelatedAttackers = Math.max(1, maxRelatedAttackers);
    }

    public int getRiskScoreThreshold() {
        return riskScoreThreshold;
    }

    public double getEventConfidenceThreshold() {
        return eventConfidenceThreshold;
    }

    public void setEventConfidenceThreshold(double eventConfidenceThreshold) {
        this.eventConfidenceThreshold = clampDouble(eventConfidenceThreshold, 0.0d, 1.0d);
    }

    public void shutdown() {
        scheduler.shutdown();
        try {
            scheduler.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        log.info("AttackChainTracker shutdown");
    }

    private int clampInt(int value, int min, int max) {
        if (value < min) {
            return min;
        }
        if (value > max) {
            return max;
        }
        return value;
    }

    private double clampDouble(double value, double min, double max) {
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            return min;
        }
        if (value < min) {
            return min;
        }
        if (value > max) {
            return max;
        }
        return value;
    }

    private double roundTo3(double value) {
        return Math.round(value * 1000.0d) / 1000.0d;
    }

    @FunctionalInterface
    public interface AlertHandler {
        void onAlert(AttackChainAlert alert);
    }

    private static class RiskComputation {
        private final int rawScore;
        private final double chainConfidence;
        private final int finalScore;

        private RiskComputation(int rawScore, double chainConfidence, int finalScore) {
            this.rawScore = rawScore;
            this.chainConfidence = chainConfidence;
            this.finalScore = finalScore;
        }
    }
}