package org.example.input_security_starter.tracker;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 攻击链告警实体
 * 当检测到攻击链时生成告警
 * 
 * 告警类型：
 * - attack_chain_detected：检测到攻击链（阶段递进）
 * 
 * 输出格式为 JSON，便于 LLM 分析
 */
public class AttackChainAlert {

    /** 告警类型 */
    private String alertType;
    
    /** 会话 ID */
    private String sessionId;
    
    /** 客户端 IP */
    private String clientIp;
    
    /** 当前攻击阶段 */
    private AttackPhase currentPhase;
    
    /** 触发的攻击阶段集合 */
    private EnumSet<AttackPhase> triggeredPhases;
    
    /** 检测到的攻击链 */
    private List<AttackSession.AttackChain> chains;
    
    /** 事件总数 */
    private int eventCount;
    
    /** 攻击链相关事件列表（包含形成攻击链的事件摘要） */
    private List<Map<String, Object>> events;
    
    /** 攻击持续时间（毫秒） */
    private long duration;
    
    /** 告警时间戳 */
    private final long timestamp;

    public AttackChainAlert() {
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * 转换为 Map 结构（用于 JSON 序列化）
     * @return Map 结构
     */
    public Map<String, Object> toMap() {
        Map<String, Object> result = new HashMap<>();
        
        result.put("alert_type", alertType);
        result.put("ts", timestamp);
        result.put("session_id", sessionId);
        result.put("client_ip", clientIp);
        
        if (currentPhase != null) {
            result.put("current_phase", currentPhase.getId());
        }
        
        if (triggeredPhases != null && !triggeredPhases.isEmpty()) {
            result.put("triggered_phases", triggeredPhases.stream()
                .map(AttackPhase::getId)
                .toArray(String[]::new));
        }
        
        if (chains != null && !chains.isEmpty()) {
            result.put("attack_chains", chains.stream()
                .map(this::chainToMap)
                .toArray(Map[]::new));
        }
        
        result.put("event_count", eventCount);
        
        if (events != null && !events.isEmpty()) {
            result.put("events", events);
        }
        
        result.put("duration_ms", duration);
        
        return result;
    }
    
    /**
     * 攻击链转 Map
     */
    private Map<String, Object> chainToMap(AttackSession.AttackChain chain) {
        Map<String, Object> map = new HashMap<>();
        map.put("from_phase", chain.getFromPhase().getId());
        map.put("to_phase", chain.getToPhase().getId());
        map.put("from_rule", chain.getFromRule());
        map.put("to_rule", chain.getToRule());
        map.put("verified", chain.isVerified());
        map.put("verification_note", chain.getVerificationNote());
        if (chain.getFromTimestamp() > 0) {
            map.put("from_ts", chain.getFromTimestamp());
        }
        if (chain.getToTimestamp() > 0) {
            map.put("to_ts", chain.getToTimestamp());
        }
        if (chain.getFromTimestamp() > 0 && chain.getToTimestamp() > 0) {
            long gapSeconds = (chain.getToTimestamp() - chain.getFromTimestamp()) / 1000;
            map.put("gap_seconds", gapSeconds);
        }
        return map;
    }

    // ==================== Getters/Setters ====================

    public String getAlertType() { return alertType; }
    public void setAlertType(String alertType) { this.alertType = alertType; }
    
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    
    public AttackPhase getCurrentPhase() { return currentPhase; }
    public void setCurrentPhase(AttackPhase currentPhase) { this.currentPhase = currentPhase; }
    
    public EnumSet<AttackPhase> getTriggeredPhases() { return triggeredPhases; }
    public void setTriggeredPhases(EnumSet<AttackPhase> triggeredPhases) { this.triggeredPhases = triggeredPhases; }
    
    public List<AttackSession.AttackChain> getChains() { return chains; }
    public void setChains(List<AttackSession.AttackChain> chains) { this.chains = chains; }
    
    public int getEventCount() { return eventCount; }
    public void setEventCount(int eventCount) { this.eventCount = eventCount; }
    
    public List<Map<String, Object>> getEvents() { return events; }
    public void setEvents(List<Map<String, Object>> events) { this.events = events; }
    
    public long getDuration() { return duration; }
    public void setDuration(long duration) { this.duration = duration; }
    
    public long getTimestamp() { return timestamp; }
}
