package org.example.input_security_starter.llm.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.example.input_security_starter.llm.ip.AbuseIpDbClient;

public class AggregatedAlert {

    private String ip;
    private AbuseIpDbClient.IpIntelligence ipIntelligence;
    private int sessionCount;
    private int totalEvents;
    private Set<String> attackPhases;
    private Map<String, Integer> attackTypes;
    private TimeRange timeRange;
    private int riskScore;
    private List<String> topPayloads;
    private List<AttackChainSummary> attackChains;
    private Set<String> targetUrls;
    private Set<String> userAgents;
    private Set<String> httpMethods;
    private Map<Integer, Integer> statusCodes;
    private Set<String> paramNames;
    private Set<String> errorMessages;
    private int successCount;
    private int failureCount;

    public AggregatedAlert() {
        this.attackPhases = new HashSet<>();
        this.attackTypes = new HashMap<>();
        this.topPayloads = new ArrayList<>();
        this.attackChains = new ArrayList<>();
        this.targetUrls = new HashSet<>();
        this.userAgents = new HashSet<>();
        this.httpMethods = new HashSet<>();
        this.statusCodes = new HashMap<>();
        this.paramNames = new HashSet<>();
        this.errorMessages = new HashSet<>();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> result = new HashMap<>();
        
        result.put("ip", ip);
        
        if (ipIntelligence != null) {
            Map<String, Object> intelMap = new HashMap<>();
            intelMap.put("abuse_score", ipIntelligence.getAbuseConfidenceScore());
            intelMap.put("total_reports", ipIntelligence.getTotalReports());
            intelMap.put("distinct_users", ipIntelligence.getNumDistinctUsers());
            intelMap.put("is_tor", ipIntelligence.isTor());
            if (ipIntelligence.getCountryCode() != null) {
                intelMap.put("country", ipIntelligence.getCountryCode());
            }
            if (ipIntelligence.getUsageType() != null) {
                intelMap.put("usage_type", ipIntelligence.getUsageType());
            }
            if (ipIntelligence.getIsp() != null) {
                intelMap.put("isp", ipIntelligence.getIsp());
            }
            result.put("ip_intelligence", intelMap);
        }
        
        result.put("session_count", sessionCount);
        result.put("total_events", totalEvents);
        result.put("attack_phases", new ArrayList<>(attackPhases));
        result.put("attack_types", attackTypes);
        
        if (timeRange != null) {
            Map<String, Object> timeMap = new HashMap<>();
            timeMap.put("start", timeRange.getStart());
            timeMap.put("end", timeRange.getEnd());
            timeMap.put("duration_minutes", timeRange.getDurationMinutes());
            result.put("time_range", timeMap);
        }
        
        result.put("risk_score", riskScore);
        
        if (!topPayloads.isEmpty()) {
            result.put("top_payloads", topPayloads.size() > 5 ? topPayloads.subList(0, 5) : topPayloads);
        }
        
        if (!attackChains.isEmpty()) {
            List<Map<String, Object>> chainsList = new ArrayList<>();
            for (AttackChainSummary chain : attackChains) {
                Map<String, Object> chainMap = new HashMap<>();
                chainMap.put("from_phase", chain.getFromPhase());
                chainMap.put("to_phase", chain.getToPhase());
                chainMap.put("from_rule", chain.getFromRule());
                chainMap.put("to_rule", chain.getToRule());
                chainsList.add(chainMap);
            }
            result.put("attack_chains", chainsList);
        }
        
        if (!targetUrls.isEmpty()) {
            result.put("target_urls", new ArrayList<>(targetUrls));
        }
        
        if (!userAgents.isEmpty()) {
            result.put("user_agents", new ArrayList<>(userAgents));
        }
        
        if (!httpMethods.isEmpty()) {
            result.put("http_methods", new ArrayList<>(httpMethods));
        }
        
        if (!statusCodes.isEmpty()) {
            result.put("status_codes", statusCodes);
            result.put("success_rate", calculateSuccessRate());
        }
        
        if (!paramNames.isEmpty()) {
            result.put("param_names", new ArrayList<>(paramNames));
        }
        
        if (!errorMessages.isEmpty()) {
            List<String> errors = new ArrayList<>(errorMessages);
            result.put("error_samples", errors.size() > 3 ? errors.subList(0, 3) : errors);
        }
        
        return result;
    }
    
    private double calculateSuccessRate() {
        int total = successCount + failureCount;
        if (total == 0) return 0.0;
        return (double) successCount / total * 100;
    }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    
    public AbuseIpDbClient.IpIntelligence getIpIntelligence() { return ipIntelligence; }
    public void setIpIntelligence(AbuseIpDbClient.IpIntelligence ipIntelligence) { this.ipIntelligence = ipIntelligence; }
    
    public int getSessionCount() { return sessionCount; }
    public void setSessionCount(int sessionCount) { this.sessionCount = sessionCount; }
    
    public int getTotalEvents() { return totalEvents; }
    public void setTotalEvents(int totalEvents) { this.totalEvents = totalEvents; }
    
    public Set<String> getAttackPhases() { return attackPhases; }
    public void addAttackPhase(String phase) { this.attackPhases.add(phase); }
    
    public Map<String, Integer> getAttackTypes() { return attackTypes; }
    public void addAttackType(String type) { 
        this.attackTypes.merge(type, 1, Integer::sum);
    }
    
    public TimeRange getTimeRange() { return timeRange; }
    public void setTimeRange(TimeRange timeRange) { this.timeRange = timeRange; }
    
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    
    public List<String> getTopPayloads() { return topPayloads; }
    public void addPayload(String payload) {
        if (payload != null && !payload.isEmpty() && !topPayloads.contains(payload)) {
            topPayloads.add(payload);
        }
    }
    
    public List<AttackChainSummary> getAttackChains() { return attackChains; }
    public void addAttackChain(AttackChainSummary chain) { this.attackChains.add(chain); }
    
    public Set<String> getTargetUrls() { return targetUrls; }
    public void addTargetUrl(String url) { this.targetUrls.add(url); }
    
    public Set<String> getUserAgents() { return userAgents; }
    public void addUserAgent(String userAgent) {
        if (userAgent != null && !userAgent.isEmpty()) {
            this.userAgents.add(userAgent);
        }
    }
    
    public Set<String> getHttpMethods() { return httpMethods; }
    public void addHttpMethod(String method) {
        if (method != null && !method.isEmpty()) {
            this.httpMethods.add(method);
        }
    }
    
    public Map<Integer, Integer> getStatusCodes() { return statusCodes; }
    public void addStatusCode(int statusCode) {
        this.statusCodes.merge(statusCode, 1, Integer::sum);
        if (statusCode >= 200 && statusCode < 300) {
            successCount++;
        } else {
            failureCount++;
        }
    }
    
    public Set<String> getParamNames() { return paramNames; }
    public void addParamName(String paramName) {
        if (paramName != null && !paramName.isEmpty()) {
            this.paramNames.add(paramName);
        }
    }
    
    public Set<String> getErrorMessages() { return errorMessages; }
    public void addErrorMessage(String errorMessage) {
        if (errorMessage != null && !errorMessage.isEmpty() && this.errorMessages.size() < 10) {
            this.errorMessages.add(errorMessage);
        }
    }
    
    public int getSuccessCount() { return successCount; }
    public int getFailureCount() { return failureCount; }

    public static class TimeRange {
        private String start;
        private String end;
        private long durationMinutes;

        public TimeRange() {}

        public TimeRange(String start, String end, long durationMinutes) {
            this.start = start;
            this.end = end;
            this.durationMinutes = durationMinutes;
        }

        public String getStart() { return start; }
        public void setStart(String start) { this.start = start; }
        public String getEnd() { return end; }
        public void setEnd(String end) { this.end = end; }
        public long getDurationMinutes() { return durationMinutes; }
        public void setDurationMinutes(long durationMinutes) { this.durationMinutes = durationMinutes; }
    }

    public static class AttackChainSummary {
        private String fromPhase;
        private String toPhase;
        private String fromRule;
        private String toRule;

        public AttackChainSummary() {}

        public AttackChainSummary(String fromPhase, String toPhase, String fromRule, String toRule) {
            this.fromPhase = fromPhase;
            this.toPhase = toPhase;
            this.fromRule = fromRule;
            this.toRule = toRule;
        }

        public String getFromPhase() { return fromPhase; }
        public void setFromPhase(String fromPhase) { this.fromPhase = fromPhase; }
        public String getToPhase() { return toPhase; }
        public void setToPhase(String toPhase) { this.toPhase = toPhase; }
        public String getFromRule() { return fromRule; }
        public void setFromRule(String fromRule) { this.fromRule = fromRule; }
        public String getToRule() { return toRule; }
        public void setToRule(String toRule) { this.toRule = toRule; }
    }
}
