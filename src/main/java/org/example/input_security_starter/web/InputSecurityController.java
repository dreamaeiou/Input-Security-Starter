package org.example.input_security_starter.web;

import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.llm.analysis.LlmAnalysisService;
import org.example.input_security_starter.llm.schedule.AlertCounter;
import org.example.input_security_starter.llm.schedule.ScheduledAnalysisTask;
import org.example.input_security_starter.notification.feishu.FeishuNotifier;
import org.example.input_security_starter.notification.wecom.WeComNotifier;
import org.example.input_security_starter.notification.dingtalk.DingTalkNotifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/input-security-api")
public class InputSecurityController {

    private final OptimizedRuleEngine ruleEngine;
    private final EventRecorder eventRecorder;
    private final LlmAnalysisService llmAnalysisService;
    private final ScheduledAnalysisTask scheduledAnalysisTask;
    private final AlertCounter alertCounter;
    private final FeishuNotifier feishuNotifier;
    private final WeComNotifier weComNotifier;
    private final DingTalkNotifier dingTalkNotifier;

    public InputSecurityController(OptimizedRuleEngine ruleEngine, EventRecorder eventRecorder,
                                   @Autowired(required = false) LlmAnalysisService llmAnalysisService,
                                   @Autowired(required = false) ScheduledAnalysisTask scheduledAnalysisTask,
                                   @Autowired(required = false) AlertCounter alertCounter,
                                   @Autowired(required = false) FeishuNotifier feishuNotifier,
                                   @Autowired(required = false) WeComNotifier weComNotifier,
                                   @Autowired(required = false) DingTalkNotifier dingTalkNotifier) {
        this.ruleEngine = ruleEngine;
        this.eventRecorder = eventRecorder;
        this.llmAnalysisService = llmAnalysisService;
        this.scheduledAnalysisTask = scheduledAnalysisTask;
        this.alertCounter = alertCounter;
        this.feishuNotifier = feishuNotifier;
        this.weComNotifier = weComNotifier;
        this.dingTalkNotifier = dingTalkNotifier;
    }

    @GetMapping("/test")
    public Map<String, Object> testInput(@RequestParam String input) {
        String rule = ruleEngine.match(input);
        Map<String, Object> result = new HashMap<>();
        result.put("input", escapeHtml(input));
        result.put("hitRule", rule);
        result.put("blocked", rule != null);
        return result;
    }
    
    private String escapeHtml(String str) {
        if (str == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            switch (c) {
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '&': sb.append("&amp;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&#x27;"); break;
                case '/': sb.append("&#x2F;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    @GetMapping("/events")
    public List<SecurityEvent> getEvents(@RequestParam(defaultValue = "50") int limit) {
        return eventRecorder.getRecentEvents(limit);
    }

    @GetMapping("/stats")
    public Map<String, Object> getAttackStats(@RequestParam(defaultValue = "24") int lastNHours) {
        Map<String, Object> result = new HashMap<>();
        result.put("totalEvents", eventRecorder.getStoredEventCount());
        
        Map<String, Integer> typeStats = eventRecorder.getAttackTypeStats();
        List<Map<String, Object>> pieData = typeStats.entrySet().stream()
            .map(e -> {
                Map<String, Object> item = new HashMap<>();
                item.put("name", e.getKey());
                item.put("value", e.getValue());
                return item;
            })
            .collect(Collectors.toList());
        result.put("typeDistribution", pieData);
        
        Map<String, Object> trendData = eventRecorder.getAttackTrendWithTypes(lastNHours);
        result.put("trend", formatTrendForECharts(trendData, lastNHours));
        
        return result;
    }
    
    private Map<String, Object> formatTrendForECharts(Map<String, Object> trendData, int lastNHours) {
        Map<String, Object> formatted = new HashMap<>();
        
        @SuppressWarnings("unchecked")
        List<String> rules = (List<String>) trendData.get("rules");
        
        @SuppressWarnings("unchecked")
        Map<Long, Map<String, Integer>> timeData = (Map<Long, Map<String, Integer>>) trendData.get("timeData");
        
        long currentHour = System.currentTimeMillis() / (1000 * 60 * 60);
        List<String> timeAxis = new ArrayList<>();
        List<Map<String, Object>> series = new ArrayList<>();
        
        for (String rule : rules) {
            Map<String, Object> seriesItem = new HashMap<>();
            seriesItem.put("name", rule);
            seriesItem.put("type", "bar");
            seriesItem.put("stack", "total");
            Map<String, Object> emphasis = new HashMap<>();
            emphasis.put("focus", "series");
            seriesItem.put("emphasis", emphasis);
            
            List<Integer> data = new ArrayList<>();
            for (int i = lastNHours - 1; i >= 0; i--) {
                long hour = currentHour - i;
                timeAxis.add(formatHourLabel(hour));
                
                Map<String, Integer> hourData = timeData.getOrDefault(hour, new HashMap<>());
                data.add(hourData.getOrDefault(rule, 0));
            }
            seriesItem.put("data", data);
            series.add(seriesItem);
        }
        
        formatted.put("timeAxis", timeAxis);
        formatted.put("series", series);
        formatted.put("rules", rules);
        return formatted;
    }
    
    private String formatHourLabel(long hour) {
        long timestamp = hour * 60 * 60 * 1000;
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("MM-dd HH:00");
        return sdf.format(new java.util.Date(timestamp));
    }

    @PostMapping("/llm/analyze")
    public Map<String, Object> triggerLlmAnalysis() {
        Map<String, Object> result = new HashMap<>();

        if (llmAnalysisService == null) {
            result.put("success", false);
            result.put("message", "LLM analysis is not enabled. Set input-security.llm.enabled=true to enable.");
            return result;
        }

        if (!llmAnalysisService.isLogFileExists()) {
            result.put("success", false);
            result.put("message", "Attack chain alert log does not exist or is empty. No analysis needed.");
            return result;
        }

        try {
            AnalysisReport report = llmAnalysisService.analyzeAttackChainAlerts();

            if (report == null) {
                result.put("success", false);
                result.put("message", "No data available for analysis.");
            } else {
                result.put("success", true);
                result.put("message", "Analysis completed successfully.");
                result.put("reportId", report.getReportId());
                result.put("report", report.toMap());
            }
        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "Analysis failed: " + e.getMessage());
        }

        return result;
    }

    @PostMapping("/llm/analyze/force")
    public Map<String, Object> forceTriggerAnalysis() {
        Map<String, Object> result = new HashMap<>();

        if (scheduledAnalysisTask == null) {
            result.put("success", false);
            result.put("message", "Scheduled analysis is not enabled. Set input-security.llm.auto-analysis.enabled=true to enable.");
            return result;
        }

        try {
            scheduledAnalysisTask.forceTrigger();
            result.put("success", true);
            result.put("message", "Force analysis triggered successfully.");
        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "Force analysis failed: " + e.getMessage());
        }

        return result;
    }

    @GetMapping("/llm/status")
    public Map<String, Object> getLlmStatus() {
        Map<String, Object> result = new HashMap<>();

        result.put("llmEnabled", llmAnalysisService != null);
        result.put("scheduledAnalysisEnabled", scheduledAnalysisTask != null);

        if (llmAnalysisService != null) {
            result.put("logFileExists", llmAnalysisService.isLogFileExists());
            result.put("reportCount", llmAnalysisService.getAllReports().size());
        }

        if (alertCounter != null) {
            AlertCounter.CounterStatus status = alertCounter.getStatus();
            Map<String, Object> counterStatus = new HashMap<>();
            counterStatus.put("unprocessedCount", status.getUnprocessedCount());
            counterStatus.put("totalAlertCount", status.getTotalAlertCount());
            counterStatus.put("alertThreshold", status.getAlertThreshold());
            counterStatus.put("lastAnalysisTime", status.getLastAnalysisTime());
            result.put("alertCounter", counterStatus);
        }

        if (scheduledAnalysisTask != null) {
            ScheduledAnalysisTask.ScheduledAnalysisStatus status = scheduledAnalysisTask.getStatus();
            Map<String, Object> scheduleStatus = new HashMap<>();
            scheduleStatus.put("enabled", status.isEnabled());
            scheduleStatus.put("scheduleIntervalHours", status.getScheduleIntervalMs() / (60 * 60 * 1000));
            scheduleStatus.put("scheduleCron", status.getScheduleCron());
            scheduleStatus.put("analysisInProgress", status.isAnalysisInProgress());
            result.put("scheduledAnalysis", scheduleStatus);
        }

        return result;
    }

    @GetMapping("/llm/reports")
    public Map<String, Object> getAllReports() {
        Map<String, Object> result = new HashMap<>();

        if (llmAnalysisService == null) {
            result.put("success", false);
            result.put("message", "LLM analysis is not enabled.");
            return result;
        }

        List<AnalysisReport> reports = llmAnalysisService.getAllReports();
        result.put("success", true);
        result.put("count", reports.size());
        result.put("reports", reports.stream()
                .map(AnalysisReport::toMap)
                .collect(Collectors.toList()));

        return result;
    }

    @GetMapping("/llm/reports/{reportId}")
    public Map<String, Object> getReportById(@PathVariable String reportId) {
        Map<String, Object> result = new HashMap<>();

        if (llmAnalysisService == null) {
            result.put("success", false);
            result.put("message", "LLM analysis is not enabled.");
            return result;
        }

        AnalysisReport report = llmAnalysisService.getReport(reportId);
        if (report == null) {
            result.put("success", false);
            result.put("message", "Report not found: " + reportId);
        } else {
            result.put("success", true);
            result.put("report", report.toMap());
        }

        return result;
    }

    @PostMapping("/feishu/test")
    public Map<String, Object> testFeishuNotification() {
        Map<String, Object> result = new HashMap<>();

        if (feishuNotifier == null) {
            result.put("success", false);
            result.put("message", "Feishu notification is not enabled. Set input-security.llm.feishu.enabled=true to enable.");
            return result;
        }

        try {
            boolean success = feishuNotifier.testNotification();
            result.put("success", success);
            result.put("message", success ? "Feishu notification test successful." : "Feishu notification test failed.");
        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "Feishu notification test failed: " + e.getMessage());
        }

        return result;
    }

    @PostMapping("/wecom/test")
    public Map<String, Object> testWeComNotification() {
        Map<String, Object> result = new HashMap<>();

        if (weComNotifier == null) {
            result.put("success", false);
            result.put("message", "WeCom notification is not enabled. Set input-security.llm.wecom.enabled=true to enable.");
            return result;
        }

        try {
            boolean success = weComNotifier.testNotification();
            result.put("success", success);
            result.put("message", success ? "WeCom notification test successful." : "WeCom notification test failed.");
        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "WeCom notification test failed: " + e.getMessage());
        }

        return result;
    }

    @PostMapping("/dingtalk/test")
    public Map<String, Object> testDingTalkNotification() {
        Map<String, Object> result = new HashMap<>();

        if (dingTalkNotifier == null) {
            result.put("success", false);
            result.put("message", "DingTalk notification is not enabled. Set input-security.llm.dingtalk.enabled=true to enable.");
            return result;
        }

        try {
            boolean success = dingTalkNotifier.testNotification();
            result.put("success", success);
            result.put("message", success ? "DingTalk notification test successful." : "DingTalk notification test failed.");
        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "DingTalk notification test failed: " + e.getMessage());
        }

        return result;
    }
}
