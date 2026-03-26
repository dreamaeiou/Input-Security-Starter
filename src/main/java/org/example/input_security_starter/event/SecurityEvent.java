package org.example.input_security_starter.event;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 安全事件实体类
 * 记录检测到的安全威胁事件，包含：
 * 1. 事件基本信息（ID、时间戳、规则名称）
 * 2. 请求信息（URL、方法、IP地址）
 * 3. 输入信息（原始输入、规范化输入、来源、参数名）
 * 4. 会话信息（会话ID、规则级别）
 * 
 * 支持构建器模式创建事件对象
 */
public class SecurityEvent {
    
    /** 事件计数器，用于生成唯一事件ID */
    private static final AtomicLong eventCounter = new AtomicLong(0);
    /** 负载最大长度，超出部分将被截断 */
    private static final int MAX_PAYLOAD_LENGTH = 200;
    
    /** 事件唯一标识 */
    private final String eventId;
    /** 触发的规则名称 */
    private final String ruleName;
    /** 输入内容片段 */
    private final String inputSnippet;
    /** 请求 URL */
    private final String url;
    /** HTTP 方法 */
    private final String method;
    /** 客户端 IP 地址 */
    private String ipAddress;
    /** 事件时间戳 */
    private final Date timestamp;
    
    /** 原始输入内容 */
    private String originalInput;
    /** 规范化后的输入内容 */
    private String normalizedInput;
    /** 输入来源（parameter/header/cookie/body） */
    private String inputSource;
    /** 参数名称 */
    private String parameterName;
    /** 会话 ID */
    private String sessionId;
    /** 规则级别（high/medium/low） */
    private String ruleLevel;
    /** User-Agent */
    private String userAgent;
    /** HTTP 状态码 */
    private Integer statusCode;
    /** 事件置信度（0~1），用于抑制误报级联 */
    private double eventConfidence = 1.0d;

    /**
     * 构造函数
     * @param ruleName 触发的规则名称
     * @param inputSnippet 输入内容片段
     * @param url 请求 URL
     * @param method HTTP 方法
     */
    public SecurityEvent(String ruleName, String inputSnippet, String url, String method) {
        this.eventId = "evt_" + System.currentTimeMillis() + "_" + String.format("%06d", eventCounter.incrementAndGet());
        this.ruleName = ruleName;
        this.inputSnippet = inputSnippet;
        this.url = url;
        this.method = method;
        this.timestamp = new Date();
    }
    
    /**
     * 构造函数（包含 IP 地址）
     * @param ruleName 触发的规则名称
     * @param inputSnippet 输入内容片段
     * @param url 请求 URL
     * @param method HTTP 方法
     * @param ipAddress 客户端 IP 地址
     */
    public SecurityEvent(String ruleName, String inputSnippet, String url, String method, String ipAddress) {
        this(ruleName, inputSnippet, url, method);
        this.ipAddress = ipAddress;
    }

    public String getEventId() { return eventId; }
    public String getRuleName() { return ruleName; }
    public String getInputSnippet() { return inputSnippet; }
    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public String getIpAddress() { return ipAddress; }
    public Date getTimestamp() { return timestamp; }
    public String getOriginalInput() { return originalInput; }
    public String getNormalizedInput() { return normalizedInput; }
    public String getInputSource() { return inputSource; }
    public String getParameterName() { return parameterName; }
    public String getSessionId() { return sessionId; }
    public String getRuleLevel() { return ruleLevel; }
    public String getUserAgent() { return userAgent; }
    public Integer getStatusCode() { return statusCode; }
    public double getEventConfidence() { return eventConfidence; }
    
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    
    /**
     * 转换为构建器
     * @return 构建器实例
     */
    public Builder toBuilder() {
        return new Builder(this);
    }
    
    /**
     * 安全事件构建器
     * 使用构建器模式创建事件对象，支持链式调用
     */
    public static class Builder {
        private final SecurityEvent event;
        
        /**
         * 构造函数
         * @param ruleName 规则名称
         * @param inputSnippet 输入片段
         * @param url 请求 URL
         * @param method HTTP 方法
         */
        public Builder(String ruleName, String inputSnippet, String url, String method) {
            event = new SecurityEvent(ruleName, inputSnippet, url, method);
        }
        
        /**
         * 构造函数（基于现有事件）
         * @param template 模板事件
         */
        public Builder(SecurityEvent template) {
            event = template;
        }
        
        public Builder ipAddress(String ipAddress) {
            event.ipAddress = ipAddress;
            return this;
        }
        
        public Builder originalInput(String originalInput) {
            event.originalInput = originalInput;
            return this;
        }
        
        public Builder normalizedInput(String normalizedInput) {
            event.normalizedInput = normalizedInput;
            return this;
        }
        
        public Builder inputSource(String inputSource) {
            event.inputSource = inputSource;
            return this;
        }
        
        public Builder parameterName(String parameterName) {
            event.parameterName = parameterName;
            return this;
        }
        
        public Builder sessionId(String sessionId) {
            event.sessionId = sessionId;
            return this;
        }
        
        public Builder ruleLevel(String ruleLevel) {
            event.ruleLevel = ruleLevel;
            return this;
        }
        
        public Builder userAgent(String userAgent) {
            event.userAgent = userAgent;
            return this;
        }
        
        public Builder statusCode(Integer statusCode) {
            event.statusCode = statusCode;
            return this;
        }

        public Builder eventConfidence(double eventConfidence) {
            event.eventConfidence = clampConfidence(eventConfidence);
            return this;
        }
        
        public SecurityEvent build() {
            return event;
        }
    }
    
    /**
     * 获取格式化的时间戳字符串
     * @return 格式化的时间戳（yyyy-MM-dd HH:mm:ss.SSS）
     */
    public String getFormattedTimestamp() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(timestamp);
    }
    
    /**
     * 转换为 Map 结构
     * 用于 JSON 序列化，字段名使用缩写以减少日志体积
     * @return 包含事件信息的 Map
     */
    public Map<String, Object> toMap() {
        Map<String, Object> result = new HashMap<>();
        
        result.put("ts", timestamp.getTime());
        result.put("rule", ruleName);
        if (ruleLevel != null) {
            result.put("level", ruleLevel);
        }
        
        if (ipAddress != null) {
            result.put("ip", ipAddress);
        }
        if (sessionId != null) {
            result.put("sid", sessionId);
        }
        if (method != null) {
            result.put("method", method);
        }
        if (url != null) {
            result.put("url", url);
        }
        if (inputSource != null) {
            result.put("source", inputSource);
        }
        if (parameterName != null) {
            result.put("param", parameterName);
        }
        
        String payload = originalInput != null ? originalInput : inputSnippet;
        if (payload != null && !payload.isEmpty()) {
            result.put("payload", truncate(payload));
        }
        
        if (normalizedInput != null && !normalizedInput.equals(payload)) {
            result.put("normalized", truncate(normalizedInput));
        }
        
        if (userAgent != null) {
            result.put("user_agent", userAgent);
        }
        
        if (statusCode != null) {
            result.put("status_code", statusCode);
        }

        if (eventConfidence > 0.0d) {
            result.put("event_confidence", roundTo3(eventConfidence));
        }
        
        return result;
    }
    
    /**
     * 截断字符串
     * 超过最大长度的部分用 "..." 表示
     * @param str 原始字符串
     * @return 截断后的字符串
     */
    private String truncate(String str) {
        if (str == null) return null;
        return str.length() > MAX_PAYLOAD_LENGTH ? str.substring(0, MAX_PAYLOAD_LENGTH) + "..." : str;
    }

    private static double clampConfidence(double value) {
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            return 1.0d;
        }
        if (value < 0.0d) {
            return 0.0d;
        }
        if (value > 1.0d) {
            return 1.0d;
        }
        return value;
    }

    private static double roundTo3(double value) {
        return Math.round(value * 1000.0d) / 1000.0d;
    }
}
