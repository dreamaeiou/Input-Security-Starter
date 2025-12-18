package org.example.input_security_starter.filiter;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.springframework.http.HttpStatus;
import org.example.input_security_starter.event.SecurityEvent;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

public class InputSecurityFilter implements Filter {

    private final InputSecurityProperties properties;
    private final OptimizedRuleEngine ruleEngine;
    private final EventRecorder eventRecorder;

    public InputSecurityFilter(InputSecurityProperties properties, OptimizedRuleEngine ruleEngine, EventRecorder eventRecorder) {
        this.properties = properties;
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!properties.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String url = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();
        
        // 获取客户端IP地址
        String clientIp = getClientIp(httpRequest);

        // 跳过内嵌 UI 路径
        if (url.startsWith("/input-security-ui")) {
            chain.doFilter(request, response);
            return;
        }

        // 检查 Parameter
        for (String paramName : httpRequest.getParameterMap().keySet()) {
            for (String value : httpRequest.getParameterValues(paramName)) {
                String rule = ruleEngine.match(value);
                if (rule != null) {
                    handleViolation(rule, value, url, method, clientIp, (HttpServletResponse) response);
                    return;
                }
            }
        }

        // 检查 Header
        Enumeration<String> headerNames = httpRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            String value = httpRequest.getHeader(name);
            String rule = ruleEngine.match(value);
            if (rule != null) {
                handleViolation(rule, value, url, method, clientIp, (HttpServletResponse) response);
                return;
            }
        }

        // 如果未命中任何规则，继续执行业务逻辑
        chain.doFilter(request, response);
    }

    private void handleViolation(String ruleName, String input, String url, String method, String clientIp, HttpServletResponse response)
            throws IOException {
        SecurityEvent event = new SecurityEvent(ruleName, input, url, method, clientIp);
        eventRecorder.record(event);

        // 拦截模式下返回错误
        if (properties.getMode() == InputSecurityProperties.Mode.BLOCK) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Input blocked by security rule: " + ruleName + "\"}");
        } else {
            // 监控模式下允许请求继续执行但记录违规
        }
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}