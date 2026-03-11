package org.example.input_security_starter.web;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * 输入安全 Web 视图控制器
 * 提供 Thymeleaf 模板页面：
 * 1. /input-security-view/test - 输入测试页面
 * 2. /input-security-view/events - 安全事件列表页面
 * 
 * 启用条件：input-security.enable-ui=true（在 InputSecurityAutoConfiguration 中控制）
 */
@Controller
@RequestMapping("/input-security-view")
public class ViewController {

    private final OptimizedRuleEngine ruleEngine;
    private final EventRecorder eventRecorder;
    private final InputSecurityProperties properties;

    /**
     * 构造函数
     * @param ruleEngine 规则引擎
     * @param eventRecorder 事件记录器
     * @param properties 安全配置属性
     */
    public ViewController(OptimizedRuleEngine ruleEngine, EventRecorder eventRecorder, InputSecurityProperties properties) {
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
        this.properties = properties;
    }

    /**
     * 输入测试页面
     * @param input 待测试的输入内容（可选）
     * @param model Thymeleaf 模型
     * @return 模板名称
     */
    @GetMapping("/test")
    public String testInput(@RequestParam(required = false) String input, Model model) {
        // 如果有输入，进行测试
        if (input != null) {
            String rule = ruleEngine.match(input);
            model.addAttribute("input", input);
            model.addAttribute("hitRule", rule);
            model.addAttribute("blocked", rule != null && properties.getMode() == InputSecurityProperties.Mode.BLOCK);
        }
        model.addAttribute("mode", properties.getMode().name().toLowerCase());
        return "test-input";
    }

    /**
     * 安全事件列表页面
     * @param limit 返回数量限制，默认 50
     * @param model Thymeleaf 模型
     * @return 模板名称
     */
    @GetMapping("/events")
    public String getEvents(@RequestParam(defaultValue = "50") int limit, Model model) {
        List<SecurityEvent> events = eventRecorder.getRecentEvents(limit);
        model.addAttribute("events", events);
        model.addAttribute("limit", limit);
        model.addAttribute("mode", properties.getMode().name().toLowerCase());
        return "security-events";
    }
    
    /**
     * 首页重定向
     * @return 重定向地址
     */
    @GetMapping("/")
    public String index() {
        return "redirect:/input-security-view/test";
    }
}
