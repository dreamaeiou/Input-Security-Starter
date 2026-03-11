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
            
            int riskScore = calculateRiskScore(aggregated);
            aggregated.setRiskScore(riskScore);
            
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

    private int calculateRiskScore(AggregatedAlert aggregated) {
        int score = 0;
        
        Map<String, Integer> attackWeights = new HashMap<>();
        attackWeights.put("xss-attack", 10);
        attackWeights.put("ldap-injection", 12);
        attackWeights.put("ssrf-attack", 15);
        attackWeights.put("path-traversal", 15);
        attackWeights.put("sql-injection", 25);
        attackWeights.put("nosql-injection", 25);
        attackWeights.put("xxe-injection", 30);
        attackWeights.put("template-injection", 35);
        attackWeights.put("deserialization-attack", 45);
        attackWeights.put("command-injection", 50);
        attackWeights.put("code-execution", 55);
        attackWeights.put("installation-attack", 70);
        attackWeights.put("c2-communication", 80);
        attackWeights.put("actions-on-objectives", 90);
        
        int payloadScore = 0;
        for (Map.Entry<String, Integer> entry : aggregated.getAttackTypes().entrySet()) {
            String attackType = entry.getKey();
            int count = entry.getValue();
            int weight = attackWeights.getOrDefault(attackType, 10);
            payloadScore += weight * Math.min(count, 5);
        }
        score += payloadScore;
        
        int phaseScore = 0;
        Set<String> phases = aggregated.getAttackPhases();
        if (phases.contains("reconnaissance")) phaseScore += 5;
        if (phases.contains("delivery")) phaseScore += 10;
        if (phases.contains("exploitation")) phaseScore += 20;
        if (phases.contains("installation")) phaseScore += 30;
        if (phases.contains("command_control")) phaseScore += 35;
        if (phases.contains("actions")) phaseScore += 40;
        score += phaseScore;
        
        int chainScore = 0;
        if (aggregated.getAttackChains() != null) {
            for (AggregatedAlert.AttackChainSummary chain : aggregated.getAttackChains()) {
                int fromOrder = getPhaseOrder(chain.getFromPhase());
                int toOrder = getPhaseOrder(chain.getToPhase());
                if (toOrder > fromOrder) {
                    chainScore += 25;
                } else if (toOrder == fromOrder) {
                    chainScore += 5;
                }
            }
        }
        score += chainScore;
        
        int intelScore = 0;
        if (aggregated.getIpIntelligence() != null) {
            AbuseIpDbClient.IpIntelligence intel = aggregated.getIpIntelligence();
            int abuseScore = intel.getAbuseConfidenceScore();
            
            if (abuseScore >= 75) {
                intelScore += 5;
            } else if (abuseScore >= 50) {
                intelScore += 10;
            } else if (abuseScore >= 25) {
                intelScore += 15;
            } else if (abuseScore < 20 && abuseScore > 0) {
                intelScore += 25;
            }
            
            if (intel.isTor()) {
                intelScore += 15;
            }
            
            if (intel.getUsageType() != null) {
                String usage = intel.getUsageType().toLowerCase();
                if (usage.contains("data center") || usage.contains("hosting")) {
                    intelScore += 10;
                }
            }
        }
        score += intelScore;
        
        int behaviorScore = 0;
        int totalEvents = aggregated.getTotalEvents();
        if (totalEvents > 50) {
            behaviorScore += 15;
        } else if (totalEvents > 20) {
            behaviorScore += 10;
        } else if (totalEvents > 10) {
            behaviorScore += 5;
        }
        
        int distinctAttackTypes = aggregated.getAttackTypes().size();
        if (distinctAttackTypes >= 4) {
            behaviorScore += 20;
        } else if (distinctAttackTypes >= 2) {
            behaviorScore += 10;
        }
        
        score += behaviorScore;
        
        return Math.min(score, 100);
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
                if (alert.getRiskScore() >= 70) highRiskCount++;
                else if (alert.getRiskScore() >= 40) mediumRiskCount++;
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
