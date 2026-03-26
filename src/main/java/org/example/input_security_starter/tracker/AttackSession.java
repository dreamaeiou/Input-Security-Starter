package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Tracks attack progress for one session (ip[:httpSessionId]).
 */
public class AttackSession {

    private final String sessionId;
    private final String clientIp;
    private String httpSessionId;

    private final long firstSeen;
    private long lastSeen;

    /** High-confidence phases only. */
    private final EnumSet<AttackPhase> triggeredPhases;
    private AttackPhase currentPhase;

    /** All events (including low-confidence). */
    private final List<SecurityEvent> events;
    private final int maxEvents;

    /** Number of events that can contribute to chain progression. */
    private int chainEventCount;

    private boolean chainDetected;
    private final List<AttackChain> chains;
    private final Set<String> chainKeys;
    private boolean alertSent;

    public AttackSession(String sessionId, String clientIp, int maxEvents) {
        this.sessionId = sessionId;
        this.clientIp = clientIp;
        this.maxEvents = maxEvents;
        this.firstSeen = System.currentTimeMillis();
        this.lastSeen = this.firstSeen;
        this.triggeredPhases = EnumSet.noneOf(AttackPhase.class);
        this.events = new ArrayList<SecurityEvent>();
        this.chains = new ArrayList<AttackChain>();
        this.chainKeys = new HashSet<String>();
        this.chainDetected = false;
        this.alertSent = false;
        this.chainEventCount = 0;
    }

    public synchronized void recordEvent(SecurityEvent event, AttackPhase phase) {
        recordEvent(event, phase, true);
    }

    public synchronized void recordEvent(SecurityEvent event, AttackPhase phase, boolean contributesToChain) {
        this.lastSeen = System.currentTimeMillis();

        if (events.size() >= maxEvents) {
            events.remove(0);
        }
        events.add(event);

        if (!contributesToChain) {
            return;
        }

        chainEventCount++;
        if (triggeredPhases.add(phase)) {
            if (currentPhase == null || phase.isAfter(currentPhase)) {
                currentPhase = phase;
            }
        }
    }

    public synchronized boolean addChain(AttackChain chain) {
        String key = chain.getFromPhase().getId() + "->" + chain.getToPhase().getId();
        if (chainKeys.contains(key)) {
            return false;
        }
        chainKeys.add(key);
        chains.add(chain);
        chainDetected = true;
        return true;
    }

    public synchronized void markAlertSent() {
        this.alertSent = true;
    }

    public boolean isExpired(long timeoutMillis) {
        return System.currentTimeMillis() - lastSeen > timeoutMillis;
    }

    public long getDuration() {
        return lastSeen - firstSeen;
    }

    public String getSessionId() { return sessionId; }
    public String getClientIp() { return clientIp; }
    public String getHttpSessionId() { return httpSessionId; }
    public long getFirstSeen() { return firstSeen; }
    public long getLastSeen() { return lastSeen; }
    public synchronized EnumSet<AttackPhase> getTriggeredPhases() { return EnumSet.copyOf(triggeredPhases); }
    public synchronized AttackPhase getCurrentPhase() { return currentPhase; }
    public synchronized List<SecurityEvent> getEvents() { return Collections.unmodifiableList(new ArrayList<SecurityEvent>(events)); }
    public synchronized int getEventCount() { return events.size(); }
    public synchronized int getChainEventCount() { return chainEventCount; }
    public synchronized boolean isChainDetected() { return chainDetected; }
    public synchronized List<AttackChain> getChains() { return Collections.unmodifiableList(new ArrayList<AttackChain>(chains)); }
    public synchronized boolean isAlertSent() { return alertSent; }

    public void setHttpSessionId(String httpSessionId) { this.httpSessionId = httpSessionId; }

    public static class AttackChain {
        private final AttackPhase fromPhase;
        private final AttackPhase toPhase;
        private final long detectedAt;
        private final String fromRule;
        private final String toRule;
        private final long fromTimestamp;
        private final long toTimestamp;
        private boolean verified;
        private String verificationNote;

        public AttackChain(AttackPhase fromPhase, AttackPhase toPhase, String fromRule, String toRule) {
            this(fromPhase, toPhase, fromRule, toRule, 0, 0);
        }

        public AttackChain(AttackPhase fromPhase, AttackPhase toPhase, String fromRule, String toRule,
                           long fromTimestamp, long toTimestamp) {
            this.fromPhase = fromPhase;
            this.toPhase = toPhase;
            this.detectedAt = System.currentTimeMillis();
            this.fromRule = fromRule;
            this.toRule = toRule;
            this.fromTimestamp = fromTimestamp;
            this.toTimestamp = toTimestamp;
            this.verified = false;
            this.verificationNote = "";
        }

        public AttackPhase getFromPhase() { return fromPhase; }
        public AttackPhase getToPhase() { return toPhase; }
        public long getDetectedAt() { return detectedAt; }
        public String getFromRule() { return fromRule; }
        public String getToRule() { return toRule; }
        public long getFromTimestamp() { return fromTimestamp; }
        public long getToTimestamp() { return toTimestamp; }
        public boolean isVerified() { return verified; }
        public String getVerificationNote() { return verificationNote; }

        public void setVerified(boolean verified) { this.verified = verified; }
        public void setVerificationNote(String note) { this.verificationNote = note; }

        public boolean validate(int maxGapMinutes) {
            if (fromTimestamp <= 0 || toTimestamp <= 0) {
                verificationNote = "missing_timestamp";
                verified = false;
                return false;
            }

            if (toTimestamp < fromTimestamp) {
                verificationNote = "invalid_time_order";
                verified = false;
                return false;
            }

            long gapMinutes = (toTimestamp - fromTimestamp) / 60000;
            if (gapMinutes > maxGapMinutes) {
                verificationNote = "time_gap_too_large:" + gapMinutes + "min";
                verified = false;
                return false;
            }

            int fromOrder = fromPhase.getOrder();
            int toOrder = toPhase.getOrder();
            if (toOrder <= fromOrder) {
                verificationNote = "no_phase_progression";
                verified = false;
                return false;
            }

            if (toOrder > fromOrder + 2) {
                verificationNote = "skipped_phase";
                verified = true;
            } else {
                verificationNote = "valid_chain";
                verified = true;
            }

            return true;
        }

        public String getDescription() {
            String status = verified ? "[VERIFIED]" : "[UNVERIFIED]";
            return String.format("%s %s -> %s (%s -> %s)",
                status, fromPhase.getDisplayName(), toPhase.getDisplayName(),
                fromRule, toRule);
        }
    }
}