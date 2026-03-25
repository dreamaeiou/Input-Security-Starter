package org.example.input_security_starter.llm.analysis;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class AnalysisReport {

    private String reportId;
    private Date analysisTime;
    private int alertCount;
    private String status;
    private String summary;

    private List<AttackType> attackTypes;
    private String riskLevel;
    private int riskScore;
    private List<String> recommendations;
    private List<TimelineEvent> timeline;
    private List<String> affectedAssets;
    private String rawResponse;
    private String errorMessage;

    private boolean attackDetected;
    private double confidence;
    private String classification;
    private String attackerSkillLevel;
    private String automationType;
    private String attackerIntent;
    private String attackerPattern;
    private double attackerIntentConfidence;
    private List<PeerAttacker> peerAttackers;
    private String attackNarrative;
    private List<String> keyIndicators;
    private int ipIntelligenceCount;
    private String windowStart;
    private String windowEnd;
    private int originalAlertCount;
    private int totalIps;
    private int highRiskIps;
    private int mediumRiskIps;
    private int lowRiskIps;
    private Double overallSuccessRate;
    private Map<Integer, Integer> statusCodeDistribution;
    private List<String> payloadSamples;
    private List<String> topAttackTypes;
    private List<String> topTargetUrls;
    private List<SourceDetail> topSources;
    private String mainAttackerIp;

    public AnalysisReport() {
        this.analysisTime = new Date();
    }

    public static class AttackType {
        private String name;
        private String description;
        private int count;
        private String severity;

        public AttackType(String name, String description, int count, String severity) {
            this.name = name;
            this.description = description;
            this.count = count;
            this.severity = severity;
        }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public int getCount() { return count; }
        public void setCount(int count) { this.count = count; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
    }

    public static class TimelineEvent {
        private long timestamp;
        private String phase;
        private String description;
        private String sourceIp;

        public TimelineEvent(long timestamp, String phase, String description, String sourceIp) {
            this.timestamp = timestamp;
            this.phase = phase;
            this.description = description;
            this.sourceIp = sourceIp;
        }

        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        public String getPhase() { return phase; }
        public void setPhase(String phase) { this.phase = phase; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public String getSourceIp() { return sourceIp; }
        public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    }

    public static class PeerAttacker {
        private String ip;
        private String relationship;
        private double confidence;
        private String relatedToIp;

        public PeerAttacker() {
        }

        public PeerAttacker(String ip, String relationship, double confidence) {
            this.ip = ip;
            this.relationship = relationship;
            this.confidence = confidence;
        }

        public PeerAttacker(String ip, String relationship, double confidence, String relatedToIp) {
            this.ip = ip;
            this.relationship = relationship;
            this.confidence = confidence;
            this.relatedToIp = relatedToIp;
        }

        public String getIp() { return ip; }
        public void setIp(String ip) { this.ip = ip; }
        public String getRelationship() { return relationship; }
        public void setRelationship(String relationship) { this.relationship = relationship; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        public String getRelatedToIp() { return relatedToIp; }
        public void setRelatedToIp(String relatedToIp) { this.relatedToIp = relatedToIp; }
    }

    public static class SourceDetail {
        private String ip;
        private int riskScore;
        private String primaryAttackType;
        private int sessionCount;
        private int totalEvents;
        private Double successRate;
        private Integer asn;
        private String country;
        private String isp;
        private String threatLevel;
        private long profileAttackCount;
        private long firstSeenTs;
        private long lastSeenTs;

        public String getIp() { return ip; }
        public void setIp(String ip) { this.ip = ip; }
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
        public String getPrimaryAttackType() { return primaryAttackType; }
        public void setPrimaryAttackType(String primaryAttackType) { this.primaryAttackType = primaryAttackType; }
        public int getSessionCount() { return sessionCount; }
        public void setSessionCount(int sessionCount) { this.sessionCount = sessionCount; }
        public int getTotalEvents() { return totalEvents; }
        public void setTotalEvents(int totalEvents) { this.totalEvents = totalEvents; }
        public Double getSuccessRate() { return successRate; }
        public void setSuccessRate(Double successRate) { this.successRate = successRate; }
        public Integer getAsn() { return asn; }
        public void setAsn(Integer asn) { this.asn = asn; }
        public String getCountry() { return country; }
        public void setCountry(String country) { this.country = country; }
        public String getIsp() { return isp; }
        public void setIsp(String isp) { this.isp = isp; }
        public String getThreatLevel() { return threatLevel; }
        public void setThreatLevel(String threatLevel) { this.threatLevel = threatLevel; }
        public long getProfileAttackCount() { return profileAttackCount; }
        public void setProfileAttackCount(long profileAttackCount) { this.profileAttackCount = profileAttackCount; }
        public long getFirstSeenTs() { return firstSeenTs; }
        public void setFirstSeenTs(long firstSeenTs) { this.firstSeenTs = firstSeenTs; }
        public long getLastSeenTs() { return lastSeenTs; }
        public void setLastSeenTs(long lastSeenTs) { this.lastSeenTs = lastSeenTs; }
    }

    public String getReportId() { return reportId; }
    public void setReportId(String reportId) { this.reportId = reportId; }
    public Date getAnalysisTime() { return analysisTime; }
    public void setAnalysisTime(Date analysisTime) { this.analysisTime = analysisTime; }
    public int getAlertCount() { return alertCount; }
    public void setAlertCount(int alertCount) { this.alertCount = alertCount; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }
    public List<AttackType> getAttackTypes() { return attackTypes; }
    public void setAttackTypes(List<AttackType> attackTypes) { this.attackTypes = attackTypes; }
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
    public List<TimelineEvent> getTimeline() { return timeline; }
    public void setTimeline(List<TimelineEvent> timeline) { this.timeline = timeline; }
    public List<String> getAffectedAssets() { return affectedAssets; }
    public void setAffectedAssets(List<String> affectedAssets) { this.affectedAssets = affectedAssets; }
    public String getRawResponse() { return rawResponse; }
    public void setRawResponse(String rawResponse) { this.rawResponse = rawResponse; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    
    public boolean isAttackDetected() { return attackDetected; }
    public void setAttackDetected(boolean attackDetected) { this.attackDetected = attackDetected; }
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    public String getClassification() { return classification; }
    public void setClassification(String classification) { this.classification = classification; }
    public String getAttackerSkillLevel() { return attackerSkillLevel; }
    public void setAttackerSkillLevel(String attackerSkillLevel) { this.attackerSkillLevel = attackerSkillLevel; }
    public String getAutomationType() { return automationType; }
    public void setAutomationType(String automationType) { this.automationType = automationType; }
    public String getAttackerIntent() { return attackerIntent; }
    public void setAttackerIntent(String attackerIntent) { this.attackerIntent = attackerIntent; }
    public String getAttackerPattern() { return attackerPattern; }
    public void setAttackerPattern(String attackerPattern) { this.attackerPattern = attackerPattern; }
    public double getAttackerIntentConfidence() { return attackerIntentConfidence; }
    public void setAttackerIntentConfidence(double attackerIntentConfidence) { this.attackerIntentConfidence = attackerIntentConfidence; }
    public List<PeerAttacker> getPeerAttackers() { return peerAttackers; }
    public void setPeerAttackers(List<PeerAttacker> peerAttackers) { this.peerAttackers = peerAttackers; }
    public String getAttackNarrative() { return attackNarrative; }
    public void setAttackNarrative(String attackNarrative) { this.attackNarrative = attackNarrative; }
    public List<String> getKeyIndicators() { return keyIndicators; }
    public void setKeyIndicators(List<String> keyIndicators) { this.keyIndicators = keyIndicators; }
    public int getIpIntelligenceCount() { return ipIntelligenceCount; }
    public void setIpIntelligenceCount(int ipIntelligenceCount) { this.ipIntelligenceCount = ipIntelligenceCount; }
    public String getWindowStart() { return windowStart; }
    public void setWindowStart(String windowStart) { this.windowStart = windowStart; }
    public String getWindowEnd() { return windowEnd; }
    public void setWindowEnd(String windowEnd) { this.windowEnd = windowEnd; }
    public int getOriginalAlertCount() { return originalAlertCount; }
    public void setOriginalAlertCount(int originalAlertCount) { this.originalAlertCount = originalAlertCount; }
    public int getTotalIps() { return totalIps; }
    public void setTotalIps(int totalIps) { this.totalIps = totalIps; }
    public int getHighRiskIps() { return highRiskIps; }
    public void setHighRiskIps(int highRiskIps) { this.highRiskIps = highRiskIps; }
    public int getMediumRiskIps() { return mediumRiskIps; }
    public void setMediumRiskIps(int mediumRiskIps) { this.mediumRiskIps = mediumRiskIps; }
    public int getLowRiskIps() { return lowRiskIps; }
    public void setLowRiskIps(int lowRiskIps) { this.lowRiskIps = lowRiskIps; }
    public Double getOverallSuccessRate() { return overallSuccessRate; }
    public void setOverallSuccessRate(Double overallSuccessRate) { this.overallSuccessRate = overallSuccessRate; }
    public Map<Integer, Integer> getStatusCodeDistribution() { return statusCodeDistribution; }
    public void setStatusCodeDistribution(Map<Integer, Integer> statusCodeDistribution) { this.statusCodeDistribution = statusCodeDistribution; }
    public List<String> getPayloadSamples() { return payloadSamples; }
    public void setPayloadSamples(List<String> payloadSamples) { this.payloadSamples = payloadSamples; }
    public List<String> getTopAttackTypes() { return topAttackTypes; }
    public void setTopAttackTypes(List<String> topAttackTypes) { this.topAttackTypes = topAttackTypes; }
    public List<String> getTopTargetUrls() { return topTargetUrls; }
    public void setTopTargetUrls(List<String> topTargetUrls) { this.topTargetUrls = topTargetUrls; }
    public List<SourceDetail> getTopSources() { return topSources; }
    public void setTopSources(List<SourceDetail> topSources) { this.topSources = topSources; }
    public String getMainAttackerIp() { return mainAttackerIp; }
    public void setMainAttackerIp(String mainAttackerIp) { this.mainAttackerIp = mainAttackerIp; }

    public Map<String, Object> toMap() {
        java.util.Map<String, Object> result = new java.util.HashMap<>();
        result.put("report_id", reportId);
        result.put("analysis_time", analysisTime.getTime());
        result.put("alert_count", alertCount);
        result.put("status", status);
        result.put("summary", summary);
        result.put("risk_level", riskLevel);
        result.put("risk_score", riskScore);
        result.put("attack_types", attackTypes);
        result.put("recommendations", recommendations);
        result.put("timeline", timeline);
        result.put("affected_assets", affectedAssets);
        
        java.util.Map<String, Object> verdict = new java.util.HashMap<>();
        verdict.put("is_attack", attackDetected);
        verdict.put("confidence", confidence);
        verdict.put("classification", classification);
        result.put("verdict", verdict);
        
        java.util.Map<String, Object> attacker = new java.util.HashMap<>();
        attacker.put("skill_level", attackerSkillLevel);
        attacker.put("automation", automationType);
        attacker.put("intent", attackerIntent);
        attacker.put("pattern", attackerPattern);
        if (attackerIntentConfidence > 0) {
            attacker.put("intent_confidence", attackerIntentConfidence);
        }
        result.put("attacker", attacker);

        if (peerAttackers != null && !peerAttackers.isEmpty()) {
            result.put("peer_attackers", peerAttackers);
        }
        
        if (attackNarrative != null || (keyIndicators != null && !keyIndicators.isEmpty())) {
            java.util.Map<String, Object> evidence = new java.util.HashMap<>();
            evidence.put("attack_narrative", attackNarrative);
            evidence.put("key_indicators", keyIndicators);
            result.put("evidence", evidence);
        }
        
        if (ipIntelligenceCount > 0) {
            result.put("ip_intelligence_count", ipIntelligenceCount);
        }

        Map<String, Object> aggregationContext = new HashMap<String, Object>();
        if (windowStart != null) {
            aggregationContext.put("window_start", windowStart);
        }
        if (windowEnd != null) {
            aggregationContext.put("window_end", windowEnd);
        }
        if (originalAlertCount > 0) {
            aggregationContext.put("original_alert_count", originalAlertCount);
        }
        if (totalIps > 0) {
            aggregationContext.put("total_ips", totalIps);
            aggregationContext.put("high_risk_ips", highRiskIps);
            aggregationContext.put("medium_risk_ips", mediumRiskIps);
            aggregationContext.put("low_risk_ips", lowRiskIps);
        }
        if (overallSuccessRate != null) {
            aggregationContext.put("success_rate", overallSuccessRate);
        }
        if (statusCodeDistribution != null && !statusCodeDistribution.isEmpty()) {
            aggregationContext.put("status_codes", statusCodeDistribution);
        }
        if (payloadSamples != null && !payloadSamples.isEmpty()) {
            aggregationContext.put("payload_samples", payloadSamples);
        }
        if (topAttackTypes != null && !topAttackTypes.isEmpty()) {
            aggregationContext.put("top_attack_types", topAttackTypes);
        }
        if (topTargetUrls != null && !topTargetUrls.isEmpty()) {
            aggregationContext.put("top_target_urls", topTargetUrls);
        }
        if (mainAttackerIp != null && !mainAttackerIp.trim().isEmpty()) {
            aggregationContext.put("main_attacker_ip", mainAttackerIp);
        }
        if (topSources != null && !topSources.isEmpty()) {
            aggregationContext.put("top_sources", topSources);
        }
        if (!aggregationContext.isEmpty()) {
            result.put("aggregation_context", aggregationContext);
        }
        
        return result;
    }
}
