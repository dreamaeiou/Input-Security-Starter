package org.example.input_security_starter.filter;

import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.engine.OptimizedRuleEngine.MatchResult;
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

        MatchResult matchResult = ruleEngine.matchDetailed(detectedInput);
        
        SecurityEvent.Builder eventBuilder = new SecurityEvent.Builder(ruleName, 
                detectedInput, url, method)
                .ipAddress(clientIp)
                .originalInput(originalInput)
                .normalizedInput(detectedInput)
                .inputSource(source)
                .parameterName(parameterName)
                .sessionId(request.getRequestedSessionId())
                .userAgent(userAgent);
        
        if (matchResult != null) {
            eventBuilder.ruleLevel(matchResult.getLevel());
        }
        
        SecurityEvent event = eventBuilder.build();
        eventRecorder.record(event);
    }
}
