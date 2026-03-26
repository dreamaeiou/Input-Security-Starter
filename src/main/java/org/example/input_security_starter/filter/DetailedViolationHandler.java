package org.example.input_security_starter.filter;

import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.engine.OptimizedRuleEngine.MatchResult;
import org.example.input_security_starter.engine.InputNormalizer;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * 详细违规处理器
 * 负责处理检测到的安全违规事件，包括：
 * 1. 创建详细的安全事件记录
 * 2. 记录原始输入和规范化输入
 * 3. 记录输入来源和参数信息
 * 4. 将事件持久化到日志
 */
public class DetailedViolationHandler {

    private static final Logger log = LoggerFactory.getLogger(DetailedViolationHandler.class);

    /** 规则引擎，用于获取匹配详情 */
    private final OptimizedRuleEngine ruleEngine;
    /** 事件记录器，用于持久化事件 */
    private final EventRecorder eventRecorder;

    /**
     * 构造函数
     * @param ruleEngine 规则引擎
     * @param eventRecorder 事件记录器
     */
    public DetailedViolationHandler(OptimizedRuleEngine ruleEngine, EventRecorder eventRecorder) {
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
    }

    /**
     * 处理安全违规事件
     * 创建详细的事件记录并持久化
     * 
     * @param originalInput 原始输入内容
     * @param detectedInput 检测到的输入内容（可能是规范化后的）
     * @param ruleName 触发的规则名称
     * @param source 输入来源（parameter/header/cookie/body）
     * @param parameterName 参数名称
     * @param clientIp 客户端 IP 地址
     * @param request HTTP 请求对象
     */
    public void handleViolation(String originalInput, String detectedInput, String ruleName, 
                               String source, String parameterName, String clientIp,
                               HttpServletRequest request) {
        
        String url = request.getRequestURI();
        String method = request.getMethod();
        String userAgent = request.getHeader("User-Agent");

        String inputForMatch = originalInput != null ? originalInput : detectedInput;
        MatchResult matchResult = ruleEngine.matchDetailed(inputForMatch);
        String normalizedInput = detectedInput;
        if (matchResult != null && matchResult.isNormalizedMatch() && originalInput != null) {
            normalizedInput = InputNormalizer.normalize(originalInput);
        }
        boolean normalizedHit = matchResult != null && matchResult.isNormalizedMatch();
        double eventConfidence = computeEventConfidence(ruleName, source, matchResult, normalizedHit);
        
        SecurityEvent.Builder eventBuilder = new SecurityEvent.Builder(ruleName, 
                detectedInput, url, method)
                .ipAddress(clientIp)
                .originalInput(originalInput)
                .normalizedInput(normalizedInput)
                .inputSource(source)
                .parameterName(parameterName)
                .sessionId(request.getRequestedSessionId())
                .userAgent(userAgent)
                .eventConfidence(eventConfidence);
        
        if (matchResult != null) {
            eventBuilder.ruleLevel(matchResult.getLevel());
        }
        
        SecurityEvent event = eventBuilder.build();
        log.debug("Security event confidence computed: rule={}, source={}, normalizedHit={}, confidence={}",
            ruleName, source, normalizedHit, event.getEventConfidence());
        eventRecorder.record(event);
    }

    private double computeEventConfidence(String ruleName, String source, MatchResult matchResult, boolean normalizedHit) {
        double ruleFactor = resolveRuleFactor(matchResult);
        double sourceFactor = resolveSourceFactor(source);
        double normalizationFactor = normalizedHit ? 0.88d : 0.98d;
        double feedbackFactor = resolveHistoricalFeedbackFactor(ruleName, source);
        return clamp(ruleFactor * sourceFactor * normalizationFactor * feedbackFactor, 0.05d, 0.99d);
    }

    private double resolveRuleFactor(MatchResult matchResult) {
        if (matchResult == null || matchResult.getLevel() == null) {
            return 0.78d;
        }
        String level = matchResult.getLevel().trim().toLowerCase();
        if ("high".equals(level)) {
            return 0.95d;
        }
        if ("medium".equals(level)) {
            return 0.84d;
        }
        if ("low".equals(level)) {
            return 0.72d;
        }
        return 0.78d;
    }

    private double resolveSourceFactor(String source) {
        if (source == null) {
            return 0.75d;
        }
        String normalized = source.trim().toLowerCase();
        if ("parameter".equals(normalized)) {
            return 0.94d;
        }
        if ("body".equals(normalized)) {
            return 0.90d;
        }
        if ("header".equals(normalized)) {
            return 0.78d;
        }
        if ("cookie".equals(normalized)) {
            return 0.74d;
        }
        return 0.75d;
    }

    private double resolveHistoricalFeedbackFactor(String ruleName, String source) {
        if (ruleName == null) {
            return 1.0d;
        }
        String normalizedRule = ruleName.trim().toLowerCase();
        if ("ssrf-attack".equals(normalizedRule) || "ldap-injection".equals(normalizedRule)) {
            return "header".equalsIgnoreCase(source) ? 0.85d : 0.90d;
        }
        if ("path-traversal".equals(normalizedRule)) {
            return 0.92d;
        }
        return 1.0d;
    }

    private double clamp(double value, double min, double max) {
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
}
