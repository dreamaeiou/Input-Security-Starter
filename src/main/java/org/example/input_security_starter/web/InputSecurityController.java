package org.example.input_security_starter.web;


import org.example.input_security_starter.engine.RuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/input-security-api")
public class InputSecurityController {

    private final RuleEngine ruleEngine;
    private final EventRecorder eventRecorder;

    public InputSecurityController(RuleEngine ruleEngine, EventRecorder eventRecorder) {
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
    }

    @GetMapping("/test")
    public Map<String, Object> testInput(@RequestParam String input) {
        String rule = ruleEngine.match(input);
        Map<String, Object> result = new HashMap<>();
        result.put("input", input);
        result.put("hitRule", rule);
        result.put("blocked", rule != null);
        return result;
    }

    @GetMapping("/events")
    public List<SecurityEvent> getEvents(@RequestParam(defaultValue = "50") int limit) {
        return eventRecorder.getRecentEvents(limit);
    }
}