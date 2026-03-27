package org.example.input_security_starter.llm.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.llm.provider.LlmProviderConfig;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LlmStructuredOutputParsingTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldParsePeerAttackersAndIntentConfidence() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            String llmJson =
                "{"
                    + "\"summary\":\"检测到多阶段攻击活动\","
                    + "\"risk_score\":88,"
                    + "\"risk_level\":\"high\","
                    + "\"attack_narrative\":\"攻击者先侦察后利用，目标集中在登录接口\","
                    + "\"recommendations\":[\"[BLOCK] 临时封禁高风险IP\",\"[PATCH] 修复登录接口注入点\",\"[MONITOR] 提升异常流量监控\",\"[REVIEW] 审查鉴权与WAF规则\",\"[IR] 启动应急溯源\"],"
                    + "\"verdict\":{\"is_attack\":true,\"confidence\":0.91,\"classification\":\"多阶段攻击\"},"
                    + "\"attacker\":{\"skill_level\":\"advanced\",\"automation\":\"semi_auto\",\"intent\":\"exploitation\",\"pattern\":\"credential_brute_force\",\"intent_confidence\":0.86},"
                    + "\"peer_attackers\":[{\"ip\":\"8.8.8.9\",\"relationship\":\"same_asn\",\"confidence\":0.95},{\"ip\":\"8.8.8.10\",\"relationship\":\"same_attack_type\",\"confidence\":0.77}],"
                    + "\"key_indicators\":[\"8.8.8.8\",\"sql-injection\",\"/api/login\"]"
                    + "}";

            LlmAnalysisService service = new LlmAnalysisService(
                new StaticJsonLlmProvider(llmJson),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertEquals("credential_brute_force", report.getAttackerPattern());
            assertEquals(0.86, report.getAttackerIntentConfidence(), 0.0001);
            assertNotNull(report.getPeerAttackers());
            assertEquals(2, report.getPeerAttackers().size());
            assertEquals("8.8.8.9", report.getPeerAttackers().get(0).getIp());

            Map<String, Object> reportMap = report.toMap();
            @SuppressWarnings("unchecked")
            Map<String, Object> attacker = (Map<String, Object>) reportMap.get("attacker");
            assertNotNull(attacker);
            assertEquals("credential_brute_force", attacker.get("pattern"));
            assertTrue(attacker.containsKey("intent_confidence"));

            @SuppressWarnings("unchecked")
            List<Object> peers = (List<Object>) reportMap.get("peer_attackers");
            assertNotNull(peers);
            assertEquals(2, peers.size());
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldRemainCompatibleWhenNewFieldsAreMissing() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            String llmJson =
                "{"
                    + "\"summary\":\"检测到攻击活动\","
                    + "\"risk_score\":72,"
                    + "\"risk_level\":\"medium\","
                    + "\"attack_narrative\":\"出现可疑注入行为\","
                    + "\"recommendations\":[\"[BLOCK] 限制异常来源\",\"[PATCH] 修复输入校验\",\"[MONITOR] 观察相关接口\",\"[REVIEW] 复核告警策略\",\"[IR] 保留取证日志\"],"
                    + "\"verdict\":{\"is_attack\":true,\"confidence\":0.8,\"classification\":\"可疑攻击\"},"
                    + "\"attacker\":{\"skill_level\":\"intermediate\",\"automation\":\"manual\",\"intent\":\"reconnaissance\"},"
                    + "\"key_indicators\":[\"sql-injection\"]"
                    + "}";

            LlmAnalysisService service = new LlmAnalysisService(
                new StaticJsonLlmProvider(llmJson),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertEquals(0.0, report.getAttackerIntentConfidence(), 0.0001);
            assertNull(report.getPeerAttackers());

            Map<String, Object> reportMap = report.toMap();
            @SuppressWarnings("unchecked")
            Map<String, Object> attacker = (Map<String, Object>) reportMap.get("attacker");
            assertNotNull(attacker);
            assertFalse(attacker.containsKey("intent_confidence"));
            assertFalse(reportMap.containsKey("peer_attackers"));
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldCalibrateConfidenceAndEnforceFiveActionRecommendations() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            String llmJson =
                "{"
                    + "\"summary\":\"检测到攻击活动\","
                    + "\"risk_score\":78,"
                    + "\"risk_level\":\"high\","
                    + "\"attack_narrative\":\"发现多阶段攻击行为\","
                    + "\"recommendations\":["
                    + "\"[BLOCK] 封禁异常源IP\","
                    + "\"[PATCH] 修复高危漏洞\","
                    + "\"[MONITOR] 监控关键接口\","
                    + "\"[REVIEW] 复核鉴权策略\","
                    + "\"[IR] 启动应急响应\","
                    + "\"关闭所有端口\","
                    + "\"更新全部软件\","
                    + "\"监控全部请求\""
                    + "],"
                    + "\"verdict\":{\"is_attack\":true,\"confidence\":0.0,\"classification\":\"可疑攻击\"},"
                    + "\"attacker\":{\"skill_level\":\"advanced\",\"automation\":\"semi_auto\",\"intent\":\"exploitation\"},"
                    + "\"key_indicators\":[\"8.8.8.8\",\"sql-injection\"]"
                    + "}";

            LlmAnalysisService service = new LlmAnalysisService(
                new StaticJsonLlmProvider(llmJson),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertTrue(report.getConfidence() > 0.5, "confidence should be calibrated above 0");

            List<String> recommendations = report.getRecommendations();
            assertNotNull(recommendations);
            assertEquals(5, recommendations.size(), "recommendations should be fixed to 5 actions");
            assertTrue(recommendations.get(0).startsWith("[BLOCK]"));
            assertTrue(recommendations.get(1).startsWith("[PATCH]"));
            assertTrue(recommendations.get(2).startsWith("[MONITOR]"));
            assertTrue(recommendations.get(3).startsWith("[REVIEW]"));
            assertTrue(recommendations.get(4).startsWith("[IR]"));
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldUseDetailedFallbackReasonWhenProviderReturnsEmpty() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            LlmAnalysisService service = new LlmAnalysisService(
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
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertEquals("degraded", report.getStatus());
            assertNotNull(report.getSummary());
            assertNotNull(report.getErrorMessage());
            String combined = String.valueOf(report.getSummary()) + " "
                + String.valueOf(report.getAttackNarrative());
            assertTrue(
                report.getErrorMessage().contains("rate_limited")
                    || combined.contains("Degraded reason")
                    || report.getErrorMessage().contains("consistency_guard")
            );
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldRejectUngroundedGenericTaggedRecommendations() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            String llmJson =
                "{"
                    + "\"summary\":\"检测到攻击活动\","
                    + "\"risk_score\":82,"
                    + "\"risk_level\":\"high\","
                    + "\"attack_narrative\":\"发现攻击行为\","
                    + "\"recommendations\":["
                    + "\"[BLOCK] 关闭不必要的端口\","
                    + "\"[PATCH] 更新系统漏洞\","
                    + "\"[MONITOR] 监控敏感数据访问\","
                    + "\"[REVIEW] 审查用户权限\","
                    + "\"[IR] 立即响应\""
                    + "],"
                    + "\"verdict\":{\"is_attack\":true,\"confidence\":0.88,\"classification\":\"攻击\"},"
                    + "\"attacker\":{\"skill_level\":\"intermediate\",\"automation\":\"semi_auto\",\"intent\":\"exploitation\"},"
                    + "\"key_indicators\":[\"sql-injection\",\"/api/login\"]"
                    + "}";

            LlmAnalysisService service = new LlmAnalysisService(
                new StaticJsonLlmProvider(llmJson),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertNotNull(report.getRecommendations());
            assertEquals(5, report.getRecommendations().size());
            assertFalse(report.getRecommendations().get(0).contains("关闭不必要的端口"));
            assertFalse(report.getRecommendations().get(1).contains("更新系统漏洞"));
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldFallbackToAggregationRiskWhenLlmScoreIsAbnormallyLow() throws Exception {
        File logFile = createHighRiskAlertLog();
        try {
            String llmJson =
                "{"
                    + "\"summary\":\"检测到可疑访问\","
                    + "\"risk_score\":10,"
                    + "\"risk_level\":\"low\","
                    + "\"attack_narrative\":\"存在异常请求\","
                    + "\"recommendations\":[\"[BLOCK] 临时封禁来源IP\",\"[PATCH] 修复输入校验\",\"[MONITOR] 监控目标接口\",\"[REVIEW] 复核策略\",\"[IR] 保留取证\"],"
                    + "\"verdict\":{\"is_attack\":true,\"confidence\":0.85,\"classification\":\"攻击\"},"
                    + "\"attacker\":{\"skill_level\":\"intermediate\",\"automation\":\"semi_auto\",\"intent\":\"exploitation\"},"
                    + "\"key_indicators\":[\"8.8.8.8\",\"actions-on-objectives\"]"
                    + "}";

            LlmAnalysisService service = new LlmAnalysisService(
                new StaticJsonLlmProvider(llmJson),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertTrue(report.getRiskScore() >= 50, "risk should fallback to aggregation baseline");
            assertEquals("degraded", report.getStatus());
            assertNotNull(report.getErrorMessage());
            assertTrue(report.getErrorMessage().contains("risk_consistency_guard_triggered"));
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldDowngradeInvalidSameAsnPeerRelationWithoutBlockingPublish() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            String llmJson =
                "{"
                    + "\"summary\":\"detected suspicious activity\","
                    + "\"risk_score\":72,"
                    + "\"risk_level\":\"medium\","
                    + "\"attack_narrative\":\"suspicious requests found\","
                    + "\"recommendations\":[\"[BLOCK] block source ip\",\"[PATCH] patch validation\",\"[MONITOR] monitor endpoint\",\"[REVIEW] review rule\",\"[IR] preserve evidence\"],"
                    + "\"verdict\":{\"is_attack\":true,\"confidence\":0.88,\"classification\":\"attack\"},"
                    + "\"attacker\":{\"skill_level\":\"intermediate\",\"automation\":\"semi_auto\",\"intent\":\"exploitation\"},"
                    + "\"peer_attackers\":[{\"ip\":\"8.8.8.9\",\"relationship\":\"same_asn\",\"confidence\":0.91}],"
                    + "\"key_indicators\":[\"8.8.8.8\",\"sql-injection\"]"
                    + "}";

            LlmAnalysisService service = new LlmAnalysisService(
                new StaticJsonLlmProvider(llmJson),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertEquals("guarded", report.getStatus());
            assertNotNull(report.getErrorMessage());
            assertTrue(report.getErrorMessage().contains("consistency_guard_triggered"));
            assertNotNull(report.getPeerAttackers());
            assertEquals(1, report.getPeerAttackers().size());
            AnalysisReport.PeerAttacker peer = report.getPeerAttackers().get(0);
            assertEquals("unverified_relation", peer.getRelationship());
            assertTrue(peer.getConfidence() <= 0.45d);
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldNormalizeRiskLevelWhenScoreAndLevelConflict() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            String llmJson =
                "{"
                    + "\"summary\":\"detected suspicious activity\","
                    + "\"risk_score\":72,"
                    + "\"risk_level\":\"low\","
                    + "\"attack_narrative\":\"suspicious requests found\","
                    + "\"recommendations\":[\"[BLOCK] block source ip\",\"[PATCH] patch validation\",\"[MONITOR] monitor endpoint\",\"[REVIEW] review rule\",\"[IR] preserve evidence\"],"
                    + "\"verdict\":{\"is_attack\":true,\"confidence\":0.88,\"classification\":\"attack\"},"
                    + "\"attacker\":{\"skill_level\":\"intermediate\",\"automation\":\"semi_auto\",\"intent\":\"exploitation\"},"
                    + "\"key_indicators\":[\"8.8.8.8\",\"sql-injection\"]"
                    + "}";

            LlmAnalysisService service = new LlmAnalysisService(
                new StaticJsonLlmProvider(llmJson),
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                4000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts(false);
            assertNotNull(report);
            assertEquals("medium", report.getRiskLevel());
            assertEquals("guarded", report.getStatus());
            assertNotNull(report.getErrorMessage());
            assertTrue(report.getErrorMessage().contains("consistency_guard_triggered"));
        } finally {
            logFile.delete();
        }
    }

    private File createMinimalAlertLog() throws Exception {
        File file = File.createTempFile("llm-structured-output", ".log");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            Map<String, Object> alert = new HashMap<String, Object>();
            alert.put("alert_type", "attack_chain_detected");
            alert.put("session_id", "sess-1");
            alert.put("client_ip", "8.8.8.8");
            alert.put("current_phase", "exploitation");
            alert.put("triggered_phases", new String[]{"reconnaissance", "delivery", "exploitation"});
            alert.put("event_count", 1);
            alert.put("duration_ms", 1200);
            alert.put("ts", System.currentTimeMillis());
            alert.put("events", new Object[]{event("sql-injection", "/api/login", "' OR 1=1 --")});
            writer.write(OBJECT_MAPPER.writeValueAsString(alert));
            writer.newLine();
        }
        return file;
    }

    private File createHighRiskAlertLog() throws Exception {
        File file = File.createTempFile("llm-structured-output-high-risk", ".log");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            Map<String, Object> alert = new HashMap<String, Object>();
            alert.put("alert_type", "attack_chain_detected");
            alert.put("session_id", "sess-high-risk");
            alert.put("client_ip", "8.8.8.8");
            alert.put("current_phase", "actions");
            alert.put("triggered_phases", new String[]{"reconnaissance", "delivery", "exploitation", "actions"});
            alert.put("event_count", 4);
            alert.put("duration_ms", 2500);
            alert.put("ts", System.currentTimeMillis());
            alert.put("events", new Object[]{
                event("sql-injection", "/api/login", "' OR 1=1 --"),
                event("command-injection", "/api/admin", "; cat /etc/passwd"),
                event("actions-on-objectives", "/api/export", "mysqldump -u root -p secret_db > dump.sql")
            });
            writer.write(OBJECT_MAPPER.writeValueAsString(alert));
            writer.newLine();
        }
        return file;
    }

    private Map<String, Object> event(String rule, String url, String payload) {
        Map<String, Object> event = new HashMap<String, Object>();
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

        StaticJsonLlmProvider(String response) {
            this(response, null);
        }

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
