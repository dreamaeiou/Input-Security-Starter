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
 * 攻击链追踪状态机
 */
public class AttackChainTracker {

    private static final Logger log = LoggerFactory.getLogger(AttackChainTracker.class);

    /** 规则名称到攻击阶段的映射 */
    private static final Map<String, AttackPhase> RULE_PHASE_MAP;
    
    static {
        Map<String, AttackPhase> map = new HashMap<>();
        
        // 1. 侦察阶段 - 信息收集、扫描探测
        map.put("ssrf-attack", AttackPhase.RECONNAISSANCE);
        map.put("path-traversal", AttackPhase.RECONNAISSANCE);
        map.put("ldap-injection", AttackPhase.RECONNAISSANCE);
        
        // 2. 投递阶段 - 攻击载荷投递
        map.put("xss-attack", AttackPhase.DELIVERY);
        map.put("sql-injection", AttackPhase.DELIVERY);
        map.put("xxe-injection", AttackPhase.DELIVERY);
        map.put("nosql-injection", AttackPhase.DELIVERY);
        map.put("template-injection", AttackPhase.DELIVERY);
        
        // 3. 利用阶段 - 漏洞利用、代码执行
        map.put("command-injection", AttackPhase.EXPLOITATION);
        map.put("code-execution", AttackPhase.EXPLOITATION);
        map.put("deserialization-attack", AttackPhase.EXPLOITATION);

        // 4. 安装阶段
        map.put("installation-attack", AttackPhase.INSTALLATION);
        
        // 5. 命令控制阶段
        map.put("c2-communication", AttackPhase.COMMAND_CONTROL);
        
        // 6. 行动阶段
        map.put("actions-on-objectives", AttackPhase.ACTIONS);
        
        RULE_PHASE_MAP = Collections.unmodifiableMap(map);
    }
    
    /**
     * 根据规则名称获取攻击阶段
     * @param ruleName 规则名称
     * @return 攻击阶段，如果规则不在映射中则返回 null
     */
    public static AttackPhase getPhaseForRule(String ruleName) {
        return RULE_PHASE_MAP.get(ruleName);
    }

    /** 会话池 */
    private final ConcurrentHashMap<String, AttackSession> sessionPool;
    
    /** 最大会话数 */
    private final int maxSessions;
    
    /** 会话超时时间（毫秒） */
    private final long sessionTimeoutMs;
    
    /** 每个会话最大保留事件数 */
    private final int maxEventsPerSession;
    
    /** 攻击链检测最小阶段数 */
    private final int minPhasesForChain;
    
    /** 告警处理器 */
    private AlertHandler alertHandler;
    
    /** 清理任务调度器 */
    private final ScheduledExecutorService scheduler;

    /**
     * 构造函数
     * @param maxSessions 最大会话数
     * @param sessionTimeoutMinutes 会话超时时间（分钟）
     * @param maxEventsPerSession 每个会话最大事件数
     * @param minPhasesForChain 攻击链检测最小阶段数
     */
    public AttackChainTracker(int maxSessions, int sessionTimeoutMinutes, 
                              int maxEventsPerSession, int minPhasesForChain) {
        this.sessionPool = new ConcurrentHashMap<>();
        this.maxSessions = maxSessions;
        this.sessionTimeoutMs = sessionTimeoutMinutes * 60 * 1000L;
        this.maxEventsPerSession = maxEventsPerSession;
        this.minPhasesForChain = minPhasesForChain;
        
        // 启动定期清理任务
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "attack-chain-cleaner");
            t.setDaemon(true);
            return t;
        });
        this.scheduler.scheduleAtFixedRate(this::cleanExpiredSessions, 1, 1, TimeUnit.MINUTES);
        
        log.info("AttackChainTracker initialized: maxSessions={}, timeout={}min", 
                 maxSessions, sessionTimeoutMinutes);
    }

    /**
     * 处理安全事件 - 核心入口
     * @param event 安全事件
     */
    public void onSecurityEvent(SecurityEvent event) {
        String ruleName = event.getRuleName();
        if (ruleName == null) {
            return;
        }
        
        // 映射到攻击阶段
        AttackPhase phase = RULE_PHASE_MAP.get(ruleName);
        if (phase == null) {
            // 不在追踪范围的规则，忽略
            return;
        }
        
        // 获取或创建会话
        String sessionId = buildSessionId(event);
        AttackSession session = getOrCreateSession(sessionId, event.getIpAddress());
        
        // 记录事件
        session.recordEvent(event, phase);
        
        // 检测攻击链
        detectAttackChain(session, phase, ruleName);
        
        // 检查是否需要告警
        checkAndAlert(session, event);
    }

    /**
     * 构建会话 ID
     * 优先使用 HTTP Session ID，否则使用 IP
     */
    private String buildSessionId(SecurityEvent event) {
        String ip = event.getIpAddress();
        String httpSessionId = event.getSessionId();
        
        if (httpSessionId != null && !httpSessionId.isEmpty()) {
            return ip + ":" + httpSessionId;
        }
        return ip;
    }

    /**
     * 获取或创建会话
     */
    private AttackSession getOrCreateSession(String sessionId, String clientIp) {
        return sessionPool.computeIfAbsent(sessionId, 
            id -> new AttackSession(id, clientIp, maxEventsPerSession));
    }
    
    /**
     * 检测攻击链
     */
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
                    existingPhase, newPhase, 
                    getLastRuleForPhase(session, existingPhase), 
                    ruleName,
                    existingTimestamp,
                    newTimestamp
                );
                
                boolean isValid = chain.validate(30);
                
                if (isValid) {
                    session.addChain(chain);
                    
                    log.info("Attack chain detected and verified: sessionId={}, chain={}, note={}", 
                             session.getSessionId(), chain.getDescription(), chain.getVerificationNote());
                } else {
                    log.debug("Attack chain rejected: sessionId={}, reason={}", 
                             session.getSessionId(), chain.getVerificationNote());
                }
            }
        }
    }

    /**
     * 获取指定阶段的最后触发规则
     */
    private String getLastRuleForPhase(AttackSession session, AttackPhase phase) {
        for (int i = session.getEvents().size() - 1; i >= 0; i--) {
            SecurityEvent event = session.getEvents().get(i);
            AttackPhase eventPhase = RULE_PHASE_MAP.get(event.getRuleName());
            if (eventPhase == phase) {
                return event.getRuleName();
            }
        }
        return "unknown";
    }
    
    /**
     * 获取指定阶段的最后触发时间戳
     */
    private long getLastTimestampForPhase(AttackSession session, AttackPhase phase) {
        for (int i = session.getEvents().size() - 1; i >= 0; i--) {
            SecurityEvent event = session.getEvents().get(i);
            AttackPhase eventPhase = RULE_PHASE_MAP.get(event.getRuleName());
            if (eventPhase == phase && event.getTimestamp() != null) {
                return event.getTimestamp().getTime();
            }
        }
        return 0;
    }

    /**
     * 检查并触发告警
     */
    private void checkAndAlert(AttackSession session, SecurityEvent event) {
        if (alertHandler == null) {
            return;
        }
        
        if (session.isAlertSent()) {
            return;
        }
        
        if (session.isChainDetected()) {
            AttackChainAlert alert = buildAlert(session, event, "attack_chain_detected");
            alertHandler.onAlert(alert);
            session.markAlertSent();
        }
    }

    /**
     * 构建告警对象
     */
    private AttackChainAlert buildAlert(AttackSession session, SecurityEvent event, String reason) {
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
        return alert;
    }
    
    /**
     * 构建事件摘要列表
     * 提取关键信息用于告警日志
     */
    private List<Map<String, Object>> buildEventSummaries(AttackSession session) {
        List<Map<String, Object>> summaries = new ArrayList<>();
        for (SecurityEvent evt : session.getEvents()) {
            Map<String, Object> summary = new HashMap<>();
            summary.put("ts", evt.getTimestamp().getTime());
            summary.put("rule", evt.getRuleName());
            summary.put("url", evt.getUrl());
            summary.put("ip", evt.getIpAddress());
            
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

    /**
     * 清理过期会话
     */
    private void cleanExpiredSessions() {
        int removed = 0;
        for (Map.Entry<String, AttackSession> entry : sessionPool.entrySet()) {
            if (entry.getValue().isExpired(sessionTimeoutMs)) {
                sessionPool.remove(entry.getKey());
                removed++;
            }
        }
        
        // 如果超过最大会话数，移除最旧的
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

    /**
     * 查找最旧的会话
     */
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

    /**
     * 获取会话池大小
     */
    public int getSessionPoolSize() {
        return sessionPool.size();
    }

    /**
     * 获取指定会话
     */
    public AttackSession getSession(String sessionId) {
        return sessionPool.get(sessionId);
    }

    /**
     * 设置告警处理器
     */
    public void setAlertHandler(AlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    /**
     * 关闭追踪器
     */
    public void shutdown() {
        scheduler.shutdown();
        try {
            scheduler.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        log.info("AttackChainTracker shutdown");
    }

    /**
     * 告警处理器接口
     */
    @FunctionalInterface
    public interface AlertHandler {
        void onAlert(AttackChainAlert alert);
    }
}
