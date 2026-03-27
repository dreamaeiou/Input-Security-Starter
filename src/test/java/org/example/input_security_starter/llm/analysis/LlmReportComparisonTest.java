package org.example.input_security_starter.llm.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.llm.provider.LlmProviderConfig;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LlmReportComparisonTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldCompareDegradedReportAgainstNormalReport() throws Exception {
        File logFile = createComparisonAlertLog();
        try {
            AnalysisReport normalReport = new LlmAnalysisService(
                new StaticJsonLlmProvider(buildNormalLlmJson(), null),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            ).analyzeAttackChainAlerts(false);

            AnalysisReport degradedReport = new LlmAnalysisService(
                new StaticJsonLlmProvider(null, "rate_limited"),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            ).analyzeAttackChainAlerts(false);

            assertNotNull(normalReport);
            assertNotNull(degradedReport);
            assertTrue(isNormalPathStatus(normalReport.getStatus()),
                "normal path should stay out of degraded/error status");
            assertEquals("degraded", degradedReport.getStatus());
            assertTrue(hasText(degradedReport.getErrorMessage()));

            Map<String, Object> normalSnapshot = buildSnapshot(normalReport);
            Map<String, Object> degradedSnapshot = buildSnapshot(degradedReport);
            List<String> diffLines = buildDiffLines(normalSnapshot, degradedSnapshot);

            System.out.println("===== REPORT DIFF: normal vs degraded =====");
            for (String line : diffLines) {
                System.out.println(line);
            }

            assertFalse(diffLines.isEmpty(), "comparison should expose report differences");
            assertTrue(containsFieldDiff(diffLines, "status"), "status diff should be present");
            assertTrue(containsFieldDiff(diffLines, "error_message"), "error_message diff should be present");

            String degradedSummary = degradedReport.getSummary() == null ? "" : degradedReport.getSummary();
            assertTrue(
                degradedSummary.contains("Degraded reason")
                    || degradedSummary.toLowerCase().contains("degraded")
                    || degradedSummary.contains("降级"),
                "degraded report summary should carry degraded hint"
            );
        } finally {
            logFile.delete();
        }
    }

    private Map<String, Object> buildSnapshot(AnalysisReport report) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("status", report.getStatus());
        out.put("error_message", report.getErrorMessage());
        out.put("summary", report.getSummary());
        out.put("risk_level", report.getRiskLevel());
        out.put("risk_score", report.getRiskScore());
        out.put("attack_detected", report.isAttackDetected());
        out.put("confidence", report.getConfidence());
        out.put("classification", report.getClassification());
        out.put("attacker_skill_level", report.getAttackerSkillLevel());
        out.put("automation_type", report.getAutomationType());
        out.put("attacker_intent", report.getAttackerIntent());
        out.put("recommendations", report.getRecommendations());
        out.put("attack_narrative", report.getAttackNarrative());
        out.put("key_indicators", report.getKeyIndicators());
        out.put("top_attack_types", report.getTopAttackTypes());
        out.put("top_target_urls", report.getTopTargetUrls());
        out.put("main_attacker_ip", report.getMainAttackerIp());
        out.put("overall_success_rate", report.getOverallSuccessRate());
        out.put("status_code_distribution", report.getStatusCodeDistribution());
        out.put("payload_samples", report.getPayloadSamples());

        Set<String> keys = new TreeSet<String>(report.toMap().keySet());
        out.put("to_map_keys", keys);
        return out;
    }

    private List<String> buildDiffLines(Map<String, Object> left, Map<String, Object> right) {
        List<String> lines = new ArrayList<String>();
        Set<String> keys = new TreeSet<String>();
        keys.addAll(left.keySet());
        keys.addAll(right.keySet());
        for (String key : keys) {
            Object lv = left.get(key);
            Object rv = right.get(key);
            if (Objects.equals(lv, rv)) {
                continue;
            }
            lines.add(
                key
                    + " | normal=" + toInlineJson(lv)
                    + " | degraded=" + toInlineJson(rv)
            );
        }
        return lines;
    }

    private boolean containsFieldDiff(List<String> lines, String field) {
        for (String line : lines) {
            if (line.startsWith(field + " |")) {
                return true;
            }
        }
        return false;
    }

    private String toInlineJson(Object value) {
        try {
            String json = OBJECT_MAPPER.writeValueAsString(value);
            if (json.length() <= 220) {
                return json;
            }
            return json.substring(0, 220) + "...";
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }

    private boolean isNormalPathStatus(String status) {
        if (!hasText(status)) {
            return false;
        }
        return !"degraded".equalsIgnoreCase(status) && !"error".equalsIgnoreCase(status);
    }

    private boolean hasText(String text) {
        return text != null && !text.trim().isEmpty();
    }

    private String buildNormalLlmJson() {
        return "{"
            + "\"summary\":\"suspicious attack activity detected\","
            + "\"risk_score\":86,"
            + "\"risk_level\":\"high\","
            + "\"attack_narrative\":\"multiple malicious payload attempts found\","
            + "\"recommendations\":["
            + "\"[BLOCK] block source ip\","
            + "\"[PATCH] patch input validation\","
            + "\"[MONITOR] monitor high risk endpoint\","
            + "\"[REVIEW] review auth and waf rules\","
            + "\"[IR] preserve incident evidence\""
            + "],"
            + "\"verdict\":{\"is_attack\":true,\"confidence\":0.9,\"classification\":\"attack\"},"
            + "\"attacker\":{\"skill_level\":\"intermediate\",\"automation\":\"semi_auto\",\"intent\":\"exploitation\"},"
            + "\"key_indicators\":[\"8.8.8.8\",\"sql-injection\",\"/api/login\"]"
            + "}";
    }

    private File createComparisonAlertLog() throws Exception {
        File file = File.createTempFile("llm-report-compare", ".log");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            Map<String, Object> alert = new LinkedHashMap<String, Object>();
            alert.put("alert_type", "attack_chain_detected");
            alert.put("session_id", "sess-compare-1");
            alert.put("client_ip", "8.8.8.8");
            alert.put("current_phase", "exploitation");
            alert.put("triggered_phases", Arrays.asList("reconnaissance", "delivery", "exploitation"));
            alert.put("event_count", 3);
            alert.put("duration_ms", 1800);
            alert.put("ts", System.currentTimeMillis());
            alert.put("events", Arrays.asList(
                event("sql-injection", "/api/login", "' OR 1=1 --"),
                event("xss-attack", "/api/search", "<script>alert(1)</script>"),
                event("command-injection", "/api/admin", "; cat /etc/passwd")
            ));
            writer.write(OBJECT_MAPPER.writeValueAsString(alert));
            writer.newLine();
        }
        return file;
    }

    private Map<String, Object> event(String rule, String url, String payload) {
        Map<String, Object> event = new LinkedHashMap<String, Object>();
        event.put("ts", System.currentTimeMillis());
        event.put("rule", rule);
        event.put("url", url);
        event.put("ip", "8.8.8.8");
        event.put("payload_preview", payload);
        event.put("method", "GET");
        return event;
    }

    private static class StaticJsonLlmProvider implements LlmProvider {
        private final String response;
        private final String failureReason;
        private final LlmProviderConfig config = new DummyConfig();

        StaticJsonLlmProvider(String response, String failureReason) {
            this.response = response;
            this.failureReason = failureReason;
        }

        @Override
        public String getName() {
            return "static-json";
        }

        @Override
        public String analyze(String prompt) {
            return response;
        }

        @Override
        public String analyzeAggregatedAlerts(String aggregatedJson) {
            return response;
        }

        @Override
        public String analyzeAttackChain(List<String> alertLogs, Map<String, Object> ipIntelligence) {
            return response;
        }

        @Override
        public boolean testConnection() {
            return true;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public LlmProviderConfig getConfig() {
            return config;
        }

        @Override
        public String getLastFailureReason() {
            return failureReason;
        }
    }

    private static class DummyConfig extends LlmProviderConfig {
        DummyConfig() {
            this.apiUrl = "http://localhost/mock";
            this.apiKey = "mock";
            this.model = "mock-model";
        }
    }
}
