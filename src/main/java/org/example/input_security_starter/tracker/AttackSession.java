package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 攻击会话状态追踪
 * 追踪单个会话（IP+SessionID）的攻击状态，包括：
 * 1. 触发的攻击阶段
 * 2. 事件序列（滑动窗口）
 * 3. 检测到的攻击链
 * 
 * 线程安全：所有修改操作通过 synchronized 保护
 */
public class AttackSession {
    
    /** 会话唯一标识（IP 或 IP+SessionID 组合） */
    private final String sessionId;
    
    /** 客户端 IP 地址 */
    private final String clientIp;
    
    /** HTTP Session ID（可选） */
    private String httpSessionId;
    
    /** 首次检测到威胁的时间戳 */
    private final long firstSeen;
    
    /** 最后一次检测到威胁的时间戳 */
    private long lastSeen;
    
    /** 触发的攻击阶段集合 */
    private final EnumSet<AttackPhase> triggeredPhases;
    
    /** 当前最高攻击阶段 */
    private AttackPhase currentPhase;
    
    /** 事件序列（滑动窗口，保留最近 N 条） */
    private final List<SecurityEvent> events;
    
    /** 最大保留事件数 */
    private final int maxEvents;
    
    /** 是否已检测到攻击链 */
    private boolean chainDetected;
    
    /** 检测到的攻击链列表 */
    private final List<AttackChain> chains;
    
    /** 已记录的攻击链键集合，用于去重 */
    private final Set<String> chainKeys;
    
    /** 是否已发送告警 */
    private boolean alertSent;
    
    /**
     * 构造函数
     * @param sessionId 会话唯一标识
     * @param clientIp 客户端 IP
     * @param maxEvents 最大保留事件数
     */
    public AttackSession(String sessionId, String clientIp, int maxEvents) {
        this.sessionId = sessionId;
        this.clientIp = clientIp;
        this.maxEvents = maxEvents;
        this.firstSeen = System.currentTimeMillis();
        this.lastSeen = this.firstSeen;
        this.triggeredPhases = EnumSet.noneOf(AttackPhase.class);
        this.events = new ArrayList<>();
        this.chains = new ArrayList<>();
        this.chainKeys = new HashSet<>();
        this.chainDetected = false;
        this.alertSent = false;
    }
    
    /**
     * 记录安全事件
     * @param event 安全事件
     * @param phase 攻击阶段
     */
    public synchronized void recordEvent(SecurityEvent event, AttackPhase phase) {
        // 更新时间戳
        this.lastSeen = System.currentTimeMillis();
        
        // 添加事件到滑动窗口
        if (events.size() >= maxEvents) {
            events.remove(0);
        }
        events.add(event);
        
        // 更新攻击阶段
        if (triggeredPhases.add(phase)) {
            // 新阶段，检查是否需要更新当前阶段
            if (currentPhase == null || phase.isAfter(currentPhase)) {
                currentPhase = phase;
            }
        }
    }
    
    /**
     * 添加检测到的攻击链（带去重）
     * @param chain 攻击链
     * @return 是否成功添加（true=新增，false=重复）
     */
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
    
    /**
     * 标记已发送告警
     */
    public synchronized void markAlertSent() {
        this.alertSent = true;
    }
    
    /**
     * 检查会话是否过期
     * @param timeoutMillis 超时时间（毫秒）
     * @return 是否过期
     */
    public boolean isExpired(long timeoutMillis) {
        return System.currentTimeMillis() - lastSeen > timeoutMillis;
    }
    
    /**
     * 获取会话持续时间（毫秒）
     * @return 持续时间
     */
    public long getDuration() {
        return lastSeen - firstSeen;
    }
    
    // ==================== Getters ====================
    
    public String getSessionId() { return sessionId; }
    public String getClientIp() { return clientIp; }
    public String getHttpSessionId() { return httpSessionId; }
    public long getFirstSeen() { return firstSeen; }
    public long getLastSeen() { return lastSeen; }
    public synchronized EnumSet<AttackPhase> getTriggeredPhases() { return EnumSet.copyOf(triggeredPhases); }
    public synchronized AttackPhase getCurrentPhase() { return currentPhase; }
    public synchronized List<SecurityEvent> getEvents() { return Collections.unmodifiableList(new ArrayList<>(events)); }
    public synchronized int getEventCount() { return events.size(); }
    public synchronized boolean isChainDetected() { return chainDetected; }
    public synchronized List<AttackChain> getChains() { return Collections.unmodifiableList(new ArrayList<>(chains)); }
    public synchronized boolean isAlertSent() { return alertSent; }
    
    public void setHttpSessionId(String httpSessionId) { this.httpSessionId = httpSessionId; }
    
    /**
     * 攻击链实体
     * 记录从一个阶段到另一个阶段的攻击进展
     */
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
        
        /**
         * 验证攻击链的有效性
         * @param maxGapMinutes 最大允许时间间隔（分钟）
         * @return 是否有效
         */
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
        
        /**
         * 获取攻击链描述
         * @return 描述字符串
         */
        public String getDescription() {
            String status = verified ? "[VERIFIED]" : "[UNVERIFIED]";
            return String.format("%s %s -> %s (%s -> %s)", 
                status, fromPhase.getDisplayName(), toPhase.getDisplayName(),
                fromRule, toRule);
        }
    }
}
