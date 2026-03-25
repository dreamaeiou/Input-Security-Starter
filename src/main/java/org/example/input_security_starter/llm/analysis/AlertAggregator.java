package org.example.input_security_starter.llm.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.ip.AbuseIpDbClient;
import org.example.input_security_starter.llm.ip.IpQueryService;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AlertAggregator {

    private static final Logger log = LoggerFactory.getLogger(AlertAggregator.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final int HIGH_RISK_THRESHOLD = 80;
    private static final int MEDIUM_RISK_THRESHOLD = 50;

    private final int maxAlertsToAggregate;
    private final IpQueryService ipQueryService;

    public AlertAggregator(IpQueryService ipQueryService, int maxAlertsToAggregate) {
        this.ipQueryService = ipQueryService;
        this.maxAlertsToAggregate = maxAlertsToAggregate;
    }

    public AlertAggregator(IpQueryService ipQueryService) {
        this(ipQueryService, 50);
    }

    public AggregationResult aggregate(List<String> alertLogs) {
        if (alertLogs == null || alertLogs.isEmpty()) {
            return new AggregationResult();
        }

        int limit = Math.min(alertLogs.size(), maxAlertsToAggregate);
        List<String> alertsToProcess = alertLogs.subList(0, limit);

        Map<String, AggregatedAlert> ipAggregations = new HashMap<>();
        Set<String> allIps = new HashSet<>();
        long minTimestamp = Long.MAX_VALUE;
        long maxTimestamp = Long.MIN_VALUE;
        int totalSessions = 0;
        int totalEvents = 0;

        for (String alertLog : alertsToProcess) {
            try {
                JsonNode root = objectMapper.readTree(alertLog);
                
                String clientIp = root.has("client_ip") ? root.get("client_ip").asText() : null;
                if (clientIp == null || clientIp.isEmpty()) continue;
                
                allIps.add(clientIp);
                
                AggregatedAlert aggregated = ipAggregations.computeIfAbsent(clientIp, ip -> {
                    AggregatedAlert a = new AggregatedAlert();
                    a.setIp(ip);
                    return a;
                });
                
                aggregated.setSessionCount(aggregated.getSessionCount() + 1);
                totalSessions++;
                
                if (root.has("ts")) {
                    long ts = root.get("ts").asLong();
                    minTimestamp = Math.min(minTimestamp, ts);
                    maxTimestamp = Math.max(maxTimestamp, ts);
                }
                
                if (root.has("triggered_phases") && root.get("triggered_phases").isArray()) {
                    for (JsonNode phase : root.get("triggered_phases")) {
                        aggregated.addAttackPhase(phase.asText());
                    }
                }
                
                if (root.has("events") && root.get("events").isArray()) {
                    for (JsonNode event : root.get("events")) {
                        totalEvents++;
                        aggregated.setTotalEvents(aggregated.getTotalEvents() + 1);
                        
                        if (event.has("rule")) {
                            aggregated.addAttackType(event.get("rule").asText());
                        }
                        
                        if (event.has("url")) {
                            aggregated.addTargetUrl(event.get("url").asText());
                        }
                        
                        if (event.has("payload_preview")) {
                            aggregated.addPayload(event.get("payload_preview").asText());
                        }
                        
                        if (event.has("ts")) {
                            long eventTs = event.get("ts").asLong();
                            minTimestamp = Math.min(minTimestamp, eventTs);
                            maxTimestamp = Math.max(maxTimestamp, eventTs);
                        }
                        
                        if (event.has("method")) {
                            aggregated.addHttpMethod(event.get("method").asText());
                        }
                        
                        if (event.has("user_agent")) {
                            aggregated.addUserAgent(event.get("user_agent").asText());
                        }
                        
                        if (event.has("status_code")) {
                            aggregated.addStatusCode(event.get("status_code").asInt());
                        }
                        
                        if (event.has("param")) {
                            aggregated.addParamName(event.get("param").asText());
                        }
                        
                        if (event.has("error_message")) {
                            aggregated.addErrorMessage(event.get("error_message").asText());
                        }
                    }
                }
                
                if (root.has("attack_chains") && root.get("attack_chains").isArray()) {
                    for (JsonNode chain : root.get("attack_chains")) {
                        AggregatedAlert.AttackChainSummary chainSummary = new AggregatedAlert.AttackChainSummary();
                        if (chain.has("from_phase")) chainSummary.setFromPhase(chain.get("from_phase").asText());
                        if (chain.has("to_phase")) chainSummary.setToPhase(chain.get("to_phase").asText());
                        if (chain.has("from_rule")) chainSummary.setFromRule(chain.get("from_rule").asText());
                        if (chain.has("to_rule")) chainSummary.setToRule(chain.get("to_rule").asText());
                        aggregated.addAttackChain(chainSummary);
                    }
                }

                if (root.has("attacker_profile") && root.get("attacker_profile").isObject()) {
                    JsonNode profile = root.get("attacker_profile");
                    if (profile.has("asn") && aggregated.getAsn() == null) {
                        int asn = readInt(profile.get("asn"), 0);
                        if (asn > 0) {
                            aggregated.setAsn(asn);
                        }
                    }
                    if (profile.has("country") && (aggregated.getCountry() == null || aggregated.getCountry().isEmpty())) {
                        aggregated.setCountry(profile.get("country").asText());
                    }
                    if (profile.has("isp") && (aggregated.getIsp() == null || aggregated.getIsp().isEmpty())) {
                        aggregated.setIsp(profile.get("isp").asText());
                    }
                    if (profile.has("total_attack_count")) {
                        long totalAttackCount = readLong(profile.get("total_attack_count"), 0L);
                        if (totalAttackCount > aggregated.getProfileAttackCount()) {
                            aggregated.setProfileAttackCount(totalAttackCount);
                        }
                    }
                    if (profile.has("first_seen_ts")) {
                        long firstSeen = readLong(profile.get("first_seen_ts"), 0L);
                        if (firstSeen > 0 && (aggregated.getFirstSeenTs() == 0L || firstSeen < aggregated.getFirstSeenTs())) {
                            aggregated.setFirstSeenTs(firstSeen);
                        }
                    }
                    if (profile.has("last_seen_ts")) {
                        long lastSeen = readLong(profile.get("last_seen_ts"), 0L);
                        if (lastSeen > aggregated.getLastSeenTs()) {
                            aggregated.setLastSeenTs(lastSeen);
                        }
                    }
                    if (profile.has("threat_level") && (aggregated.getThreatLevel() == null || aggregated.getThreatLevel().isEmpty())) {
                        aggregated.setThreatLevel(profile.get("threat_level").asText());
                    }
                }

                if (root.has("related_attackers") && root.get("related_attackers").isArray()) {
                    for (JsonNode related : root.get("related_attackers")) {
                        if (related.has("ip")) {
                            aggregated.addRelatedIp(related.get("ip").asText());
                        }
                    }
                }
                
            } catch (Exception e) {
                log.debug("Failed to parse alert log for aggregation: {}", e.getMessage());
            }
        }

        Map<String, AbuseIpDbClient.IpIntelligence> ipIntelligence = null;
        if (ipQueryService != null && !allIps.isEmpty()) {
            ipIntelligence = ipQueryService.getIpIntelligenceForAnalysis(allIps);
        }

        for (Map.Entry<String, AggregatedAlert> entry : ipAggregations.entrySet()) {
            AggregatedAlert aggregated = entry.getValue();
            
            if (ipIntelligence != null && ipIntelligence.containsKey(entry.getKey())) {
                aggregated.setIpIntelligence(ipIntelligence.get(entry.getKey()));
            }
            
            RiskScoreResult riskScoreResult = calculateRiskScore(aggregated);
            aggregated.setRiskScore(riskScoreResult.finalScore);
            aggregated.setRiskBreakdown(riskScoreResult.toMap());
            
            if (minTimestamp != Long.MAX_VALUE && maxTimestamp != Long.MIN_VALUE) {
                AggregatedAlert.TimeRange timeRange = new AggregatedAlert.TimeRange(
                    DATE_FORMAT.format(new Date(minTimestamp)),
                    DATE_FORMAT.format(new Date(maxTimestamp)),
                    (maxTimestamp - minTimestamp) / 60000
                );
                aggregated.setTimeRange(timeRange);
            }
        }

        List<AggregatedAlert> aggregatedList = new ArrayList<>(ipAggregations.values());
        aggregatedList.sort((a, b) -> Integer.compare(b.getRiskScore(), a.getRiskScore()));

        AggregationResult result = new AggregationResult();
        result.setAggregatedAlerts(aggregatedList);
        result.setTotalIps(allIps.size());
        result.setTotalSessions(totalSessions);
        result.setTotalEvents(totalEvents);
        result.setProcessedAlerts(limit);
        result.setOriginalAlerts(alertLogs.size());
        
        if (minTimestamp != Long.MAX_VALUE) {
            result.setStartTime(DATE_FORMAT.format(new Date(minTimestamp)));
        }
        if (maxTimestamp != Long.MIN_VALUE) {
            result.setEndTime(DATE_FORMAT.format(new Date(maxTimestamp)));
        }

        log.info("Aggregated {} alerts into {} IP groups (total sessions: {}, events: {})", 
                limit, aggregatedList.size(), totalSessions, totalEvents);

        return result;
    }

    private int readInt(JsonNode node, int defaultValue) {
        if (node == null || node.isNull()) {
            return defaultValue;
        }
        if (node.isNumber()) {
            return node.asInt(defaultValue);
        }
        try {
            return Integer.parseInt(node.asText().trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private long readLong(JsonNode node, long defaultValue) {
        if (node == null || node.isNull()) {
            return defaultValue;
        }
        if (node.isNumber()) {
            return node.asLong(defaultValue);
        }
        try {
            return Long.parseLong(node.asText().trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private RiskScoreResult calculateRiskScore(AggregatedAlert aggregated) {
        RiskScoreResult result = new RiskScoreResult();
        
        Map<String, Integer> attackWeights = new HashMap<>();
        attackWeights.put("port-scan", 2);
        attackWeights.put("info-disclosure", 3);
        attackWeights.put("directory-traversal-attempt", 6);
        attackWeights.put("xss-attack", 8);
        attackWeights.put("ldap-injection", 10);
        attackWeights.put("ssrf-attack", 12);
        attackWeights.put("path-traversal", 14);
        attackWeights.put("sql-injection", 20);
        attackWeights.put("nosql-injection", 20);
        attackWeights.put("xxe-injection", 24);
        attackWeights.put("template-injection", 28);
        attackWeights.put("deserialization-attack", 32);
        attackWeights.put("command-injection", 36);
        attackWeights.put("code-execution", 40);
        attackWeights.put("file-upload", 12);
        attackWeights.put("installation-attack", 48);
        attackWeights.put("c2-communication", 60);
        attackWeights.put("actions-on-objectives", 70);
        
        int payloadScore = 0;
        for (Map.Entry<String, Integer> entry : aggregated.getAttackTypes().entrySet()) {
            String attackType = entry.getKey();
            int count = entry.getValue();
            int weight = attackWeights.getOrDefault(attackType, 6);
            payloadScore += weight * Math.min(count, 3);
        }
        payloadScore = Math.min(payloadScore, 32);
        result.payloadScore = payloadScore;
        
        int phaseScore = 0;
        Set<String> phases = aggregated.getAttackPhases();
        if (phases.contains("reconnaissance")) phaseScore += 4;
        if (phases.contains("delivery")) phaseScore += 8;
        if (phases.contains("exploitation")) phaseScore += 14;
        if (phases.contains("installation")) phaseScore += 20;
        if (phases.contains("command_control")) phaseScore += 24;
        if (phases.contains("actions")) phaseScore += 28;
        phaseScore = Math.min(phaseScore, 20);
        result.phaseScore = phaseScore;
        
        int chainScore = 0;
        if (aggregated.getAttackChains() != null) {
            for (AggregatedAlert.AttackChainSummary chain : aggregated.getAttackChains()) {
                int fromOrder = getPhaseOrder(chain.getFromPhase());
                int toOrder = getPhaseOrder(chain.getToPhase());
                if (toOrder > fromOrder) {
                    chainScore += 10;
                } else if (toOrder == fromOrder) {
                    chainScore += 3;
                }
            }
        }
        chainScore = Math.min(chainScore, 12);
        result.chainScore = chainScore;
        
        int intelScore = 0;
        if (aggregated.getIpIntelligence() != null) {
            AbuseIpDbClient.IpIntelligence intel = aggregated.getIpIntelligence();
            int abuseScore = intel.getAbuseConfidenceScore();
            
            if (abuseScore >= 75) {
                intelScore += 18;
            } else if (abuseScore >= 50) {
                intelScore += 12;
            } else if (abuseScore >= 25) {
                intelScore += 7;
            } else if (abuseScore > 0) {
                intelScore += 3;
            }
            
            if (intel.isTor()) {
                intelScore += 8;
            }
            
            if (intel.getUsageType() != null) {
                String usage = intel.getUsageType().toLowerCase();
                if (usage.contains("data center") || usage.contains("hosting")) {
                    intelScore += 2;
                }
            }

            int totalReports = intel.getTotalReports();
            if (totalReports >= 30) {
                intelScore += 4;
            } else if (totalReports >= 10) {
                intelScore += 2;
            } else if (totalReports > 0) {
                intelScore += 1;
            }
        }
        intelScore = Math.min(intelScore, 16);
        result.intelScore = intelScore;
        
        int behaviorScore = 0;
        int totalEvents = aggregated.getTotalEvents();
        if (totalEvents > 50) {
            behaviorScore += 10;
        } else if (totalEvents > 20) {
            behaviorScore += 6;
        } else if (totalEvents > 10) {
            behaviorScore += 3;
        }
        
        int distinctAttackTypes = aggregated.getAttackTypes().size();
        if (distinctAttackTypes >= 4) {
            behaviorScore += 8;
        } else if (distinctAttackTypes >= 2) {
            behaviorScore += 4;
        }
        behaviorScore = Math.min(behaviorScore, 12);
        
        result.behaviorScore = behaviorScore;

        int rawScore = payloadScore + phaseScore + chainScore + intelScore + behaviorScore;
        result.rawScore = rawScore;

        boolean hasExploitationEvidence = hasExploitationEvidence(aggregated);
        boolean hasCriticalEvidence = hasCriticalEvidence(aggregated);
        boolean weakReputation = isWeakReputation(aggregated.getIpIntelligence());
        result.hasExploitationEvidence = hasExploitationEvidence;
        result.hasCriticalEvidence = hasCriticalEvidence;
        result.weakReputation = weakReputation;

        int finalScore = rawScore;

        // 无利用证据时，不允许风险分轻易封顶，降低“全是100分”的噪声。
        if (!hasExploitationEvidence) {
            finalScore = Math.min(finalScore, 75);
            result.capReason = "no_exploitation_evidence";
        }

        // 情报可信度弱且缺少利用证据时进一步降权，避免“Abuse=0仍冲高”。
        if (weakReputation && !hasExploitationEvidence) {
            finalScore = Math.max(0, finalScore - 8);
            if (result.capReason == null) {
                result.capReason = "weak_reputation_no_exploitation";
            }
        }

        // 有利用证据但缺少“高置信高破坏”证据时，不应轻易进入90+。
        if (hasExploitationEvidence && !hasCriticalEvidence) {
            finalScore = Math.min(finalScore, 89);
            if (result.capReason == null) {
                result.capReason = "no_critical_evidence";
            }
        }

        // 内网/保留网段默认不按互联网外部攻击源对待，避免比赛样例误导。
        if (isNonRoutableOrDocumentationIp(aggregated.getIp())) {
            finalScore = Math.min(finalScore, 78);
            finalScore = Math.max(0, finalScore - 8);
            result.nonRoutableIp = true;
            if (result.capReason == null) {
                result.capReason = "non_routable_or_doc_ip";
            }
        }

        result.finalScore = Math.min(finalScore, 100);
        return result;
    }

    private boolean hasExploitationEvidence(AggregatedAlert aggregated) {
        if (aggregated == null) {
            return false;
        }

        Set<String> phases = aggregated.getAttackPhases();
        if (phases != null && (phases.contains("exploitation")
                || phases.contains("installation")
                || phases.contains("command_control")
                || phases.contains("actions"))) {
            return true;
        }

        for (String type : aggregated.getAttackTypes().keySet()) {
            String t = type == null ? "" : type.toLowerCase();
            if (t.contains("sql-injection")
                    || t.contains("nosql-injection")
                    || t.contains("template-injection")
                    || t.contains("command-injection")
                    || t.contains("code-execution")
                    || t.contains("deserialization")
                    || t.contains("xxe-injection")
                    || t.contains("installation-attack")
                    || t.contains("c2-communication")
                    || t.contains("actions-on-objectives")) {
                return true;
            }
        }

        for (AggregatedAlert.AttackChainSummary chain : aggregated.getAttackChains()) {
            int toOrder = getPhaseOrder(chain.getToPhase());
            if (toOrder >= 3) {
                return true;
            }
        }

        return false;
    }

    private boolean isWeakReputation(AbuseIpDbClient.IpIntelligence intel) {
        if (intel == null) {
            return true;
        }

        boolean zeroAbuse = intel.getAbuseConfidenceScore() <= 0;
        boolean zeroReports = intel.getTotalReports() <= 0;
        boolean nonTor = !intel.isTor();
        return zeroAbuse && zeroReports && nonTor;
    }

    private boolean hasCriticalEvidence(AggregatedAlert aggregated) {
        if (aggregated == null) {
            return false;
        }
        Set<String> phases = aggregated.getAttackPhases();
        if (phases != null && (phases.contains("installation")
                || phases.contains("command_control")
                || phases.contains("actions"))) {
            return true;
        }
        for (String type : aggregated.getAttackTypes().keySet()) {
            String t = type == null ? "" : type.toLowerCase();
            if (t.contains("code-execution")
                    || t.contains("command-injection")
                    || t.contains("deserialization")
                    || t.contains("installation-attack")
                    || t.contains("c2-communication")
                    || t.contains("actions-on-objectives")) {
                return true;
            }
        }
        return false;
    }

    private boolean isNonRoutableOrDocumentationIp(String ip) {
        if (ip == null) {
            return false;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int first;
        int second;
        try {
            first = Integer.parseInt(parts[0]);
            second = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        return ip.startsWith("10.")
            || ip.startsWith("127.")
            || ip.startsWith("169.254.")
            || ip.startsWith("192.168.")
            || (first == 172 && second >= 16 && second <= 31)
            || ip.startsWith("192.0.2.")
            || ip.startsWith("198.51.100.")
            || ip.startsWith("203.0.113.");
    }

    private static class RiskScoreResult {
        private int payloadScore;
        private int phaseScore;
        private int chainScore;
        private int intelScore;
        private int behaviorScore;
        private int rawScore;
        private int finalScore;
        private boolean hasExploitationEvidence;
        private boolean hasCriticalEvidence;
        private boolean weakReputation;
        private boolean nonRoutableIp;
        private String capReason;

        private Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("payload_score", payloadScore);
            map.put("phase_score", phaseScore);
            map.put("chain_score", chainScore);
            map.put("intel_score", intelScore);
            map.put("behavior_score", behaviorScore);
            map.put("raw_score", rawScore);
            map.put("final_score", finalScore);
            map.put("has_exploitation_evidence", hasExploitationEvidence);
            map.put("has_critical_evidence", hasCriticalEvidence);
            map.put("weak_reputation", weakReputation);
            map.put("non_routable_ip", nonRoutableIp);
            if (capReason != null) {
                map.put("cap_reason", capReason);
            }
            return map;
        }
    }
    
    private int getPhaseOrder(String phase) {
        if (phase == null) return 0;
        switch (phase.toLowerCase()) {
            case "reconnaissance": return 1;
            case "delivery": return 2;
            case "exploitation": return 3;
            case "installation": return 4;
            case "command_control":
            case "command & control":
            case "c2": return 5;
            case "actions":
            case "actions on objectives": return 6;
            default: return 0;
        }
    }

    public static class AggregationResult {
        private List<AggregatedAlert> aggregatedAlerts;
        private int totalIps;
        private int totalSessions;
        private int totalEvents;
        private int processedAlerts;
        private int originalAlerts;
        private String startTime;
        private String endTime;

        public AggregationResult() {
            this.aggregatedAlerts = new ArrayList<>();
        }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new HashMap<>();
            
            result.put("summary", createSummary());
            
            List<Map<String, Object>> alertsList = new ArrayList<>();
            for (AggregatedAlert alert : aggregatedAlerts) {
                alertsList.add(alert.toMap());
            }
            result.put("aggregated_alerts", alertsList);
            
            return result;
        }

        private Map<String, Object> createSummary() {
            Map<String, Object> summary = new HashMap<>();
            summary.put("total_ips", totalIps);
            summary.put("total_sessions", totalSessions);
            summary.put("total_events", totalEvents);
            summary.put("processed_alerts", processedAlerts);
            summary.put("original_alerts", originalAlerts);
            
            if (startTime != null) {
                summary.put("start_time", startTime);
            }
            if (endTime != null) {
                summary.put("end_time", endTime);
            }
            
            int highRiskCount = 0;
            int mediumRiskCount = 0;
            int lowRiskCount = 0;
            for (AggregatedAlert alert : aggregatedAlerts) {
                if (alert.getRiskScore() >= HIGH_RISK_THRESHOLD) highRiskCount++;
                else if (alert.getRiskScore() >= MEDIUM_RISK_THRESHOLD) mediumRiskCount++;
                else lowRiskCount++;
            }
            summary.put("high_risk_ips", highRiskCount);
            summary.put("medium_risk_ips", mediumRiskCount);
            summary.put("low_risk_ips", lowRiskCount);
            
            return summary;
        }

        public List<AggregatedAlert> getAggregatedAlerts() { return aggregatedAlerts; }
        public void setAggregatedAlerts(List<AggregatedAlert> aggregatedAlerts) { this.aggregatedAlerts = aggregatedAlerts; }
        public int getTotalIps() { return totalIps; }
        public void setTotalIps(int totalIps) { this.totalIps = totalIps; }
        public int getTotalSessions() { return totalSessions; }
        public void setTotalSessions(int totalSessions) { this.totalSessions = totalSessions; }
        public int getTotalEvents() { return totalEvents; }
        public void setTotalEvents(int totalEvents) { this.totalEvents = totalEvents; }
        public int getProcessedAlerts() { return processedAlerts; }
        public void setProcessedAlerts(int processedAlerts) { this.processedAlerts = processedAlerts; }
        public int getOriginalAlerts() { return originalAlerts; }
        public void setOriginalAlerts(int originalAlerts) { this.originalAlerts = originalAlerts; }
        public String getStartTime() { return startTime; }
        public void setStartTime(String startTime) { this.startTime = startTime; }
        public String getEndTime() { return endTime; }
        public void setEndTime(String endTime) { this.endTime = endTime; }
    }
}
