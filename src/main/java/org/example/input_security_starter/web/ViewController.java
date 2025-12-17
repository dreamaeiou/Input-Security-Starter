package org.example.input_security_starter.web;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.RuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
@RequestMapping("/input-security-view")
public class ViewController {

    private final RuleEngine ruleEngine;
    private final EventRecorder eventRecorder;
    private final InputSecurityProperties properties;

    public ViewController(RuleEngine ruleEngine, EventRecorder eventRecorder, InputSecurityProperties properties) {
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
        this.properties = properties;
    }

    @GetMapping("/test")
    public String testInput(@RequestParam(required = false) String input, Model model) {
        if (input != null) {
            String rule = ruleEngine.match(input);
            model.addAttribute("input", input);
            model.addAttribute("hitRule", rule);
            model.addAttribute("blocked", rule != null && properties.getMode() == InputSecurityProperties.Mode.BLOCK);
        }
        model.addAttribute("mode", properties.getMode().name().toLowerCase());
        return "test-input";
    }

    @GetMapping("/events")
    public String getEvents(@RequestParam(defaultValue = "50") int limit, Model model) {
        List<SecurityEvent> events = eventRecorder.getRecentEvents(limit);
        model.addAttribute("events", events);
        model.addAttribute("limit", limit);
        model.addAttribute("mode", properties.getMode().name().toLowerCase());
        return "security-events";
    }
    
    @GetMapping("/")
    public String index() {
        return "redirect:/input-security-view/test";
    }
}