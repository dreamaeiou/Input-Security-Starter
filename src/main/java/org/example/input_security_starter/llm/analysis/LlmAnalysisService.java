package org.example.input_security_starter.llm.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.example.input_security_starter.llm.ip.AbuseIpDbClient;
import org.example.input_security_starter.llm.ip.IpQueryService;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.notification.FeishuNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LlmAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(LlmAnalysisService.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(\\d{1,3}\\.){3}\\d{1,3}\\b");

    private final LlmProvider llmProvider;
    private final AbuseIpDbClient abuseIpDbClient;
    private final IpQueryService ipQueryService;
    private final String alertLogPath;
    private final int maxAlertsPerAnalysis;
    private final int maxPromptChars;
    private final int maxIpsPerAnalysis;
    private final int maxEventsPerIp;
    private final long analysisTimeoutMs;
    private final ConcurrentHashMap<String, AnalysisReport> reportCache;
    private final FeishuNotifier feishuNotifier;
    private final AtomicBoolean analysisInProgress;
    private final ExecutorService llmExecutor;

    public LlmAnalysisService(LlmProvider llmProvider, AbuseIpDbClient abuseIpDbClient, IpQueryService ipQueryService, String alertLogPath) {
        this(llmProvider, abuseIpDbClient, ipQueryService, alertLogPath, 50, null);
    }

    public LlmAnalysisService(LlmProvider llmProvider, AbuseIpDbClient abuseIpDbClient, IpQueryService ipQueryService, String alertLogPath, int maxAlertsPerAnalysis) {
        this(llmProvider, abuseIpDbClient, ipQueryService, alertLogPath, maxAlertsPerAnalysis, null);
    }

    public LlmAnalysisService(
        LlmProvider llmProvider,
        AbuseIpDbClient abuseIpDbClient,
        IpQueryService ipQueryService,
        String alertLogPath,
        int maxAlertsPerAnalysis,
        FeishuNotifier feishuNotifier
    ) {
        this(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            maxAlertsPerAnalysis,
            24_000,
            50,
            50,
            90_000,
            feishuNotifier
        );
    }

    public LlmAnalysisService(
        LlmProvider llmProvider,
        AbuseIpDbClient abuseIpDbClient,
        IpQueryService ipQueryService,
        String alertLogPath,
        int maxAlertsPerAnalysis,
        int maxPromptChars,
        int maxIpsPerAnalysis,
        int maxEventsPerIp,
        long analysisTimeoutMs,
        FeishuNotifier feishuNotifier
    ) {
        this.llmProvider = llmProvider;
        this.abuseIpDbClient = abuseIpDbClient;
        this.ipQueryService = ipQueryService;
        this.alertLogPath = alertLogPath;
        this.maxAlertsPerAnalysis = maxAlertsPerAnalysis;
        this.maxPromptChars = Math.max(1024, maxPromptChars);
        this.maxIpsPerAnalysis = Math.max(1, maxIpsPerAnalysis);
        this.maxEventsPerIp = Math.max(1, maxEventsPerIp);
        this.analysisTimeoutMs = Math.max(1000, analysisTimeoutMs);
        this.feishuNotifier = feishuNotifier;
        this.reportCache = new ConcurrentHashMap<String, AnalysisReport>();
        this.analysisInProgress = new AtomicBoolean(false);
        this.llmExecutor = Executors.newCachedThreadPool();
    }

    public LlmAnalysisService(LlmProvider llmProvider, AbuseIpDbClient abuseIpDbClient, String alertLogPath) {
        this(llmProvider, abuseIpDbClient, null, alertLogPath, 50, null);
    }

    public AnalysisReport analyzeAttackChainAlerts() {
        return analyzeAttackChainAlerts(true);
    }

    public AnalysisReport analyzeAttackChainAlerts(boolean notifyFeishu) {
        if (!analysisInProgress.compareAndSet(false, true)) {
            return createErrorReport("Analysis already in progress", 0);
        }

        long startMs = System.currentTimeMillis();
        try {
            File logFile = new File(alertLogPath);
            if (!logFile.exists() || logFile.length() == 0) {
                log.info("Attack chain alert log is unavailable or empty: {}", alertLogPath);
                return null;
            }

            List<String> alertLogs = readAlertLogs(logFile);
            if (alertLogs.isEmpty()) {
                log.info("No valid alert logs found in file: {}", alertLogPath);
                return null;
            }

            AlertAggregator aggregator = new AlertAggregator(ipQueryService, maxAlertsPerAnalysis);
            AlertAggregator.AggregationResult aggregationResult = aggregator.aggregate(alertLogs);

            if (isBudgetExceeded(startMs)) {
                return createLocalFallbackReport(aggregationResult, "Analysis timeout before LLM invocation", alertLogs.size());
            }

            String aggregatedJson = OBJECT_MAPPER.writeValueAsString(aggregationResult.toMap());
            String budgetedJson = applyInputBudget(aggregatedJson);

            if (isBudgetExceeded(startMs)) {
                return createLocalFallbackReport(aggregationResult, "Analysis timeout after input budgeting", alertLogs.size());
            }

            String llmResponse = callLlmWithTimeout(budgetedJson, startMs);
            AnalysisReport report;
            if (llmResponse == null || llmResponse.trim().isEmpty()) {
                report = createLocalFallbackReport(aggregationResult, "LLM returned empty response", aggregationResult.getProcessedAlerts());
            } else if (!validateLlmOutput(llmResponse)) {
                report = createLocalFallbackReport(aggregationResult, "LLM output validation failed", aggregationResult.getProcessedAlerts());
            } else {
                report = parseLlmResponse(llmResponse, aggregationResult.getProcessedAlerts());
            }

            applyRiskFallbackFromAggregation(report, aggregationResult);
            report.setIpIntelligenceCount(aggregationResult.getTotalIps());
            report.setAlertCount(aggregationResult.getProcessedAlerts());
            reportCache.put(report.getReportId(), report);

            if (notifyFeishu && feishuNotifier != null && feishuNotifier.isEnabled()) {
                try {
                    feishuNotifier.notifyAnalysisComplete(report);
                } catch (Exception e) {
                    log.error("Failed to send Feishu notification: {}", e.getMessage(), e);
                }
            }
            return report;
        } catch (Exception e) {
            log.error("Failed to analyze attack chain alerts: {}", e.getMessage(), e);
            return createErrorReport(e.getMessage(), 0);
        } finally {
            analysisInProgress.set(false);
        }
    }

    private String callLlmWithTimeout(final String aggregatedJson, long startMs) {
        long remainMs = analysisTimeoutMs - (System.currentTimeMillis() - startMs);
        if (remainMs <= 0) {
            return null;
        }

        Future<String> future = llmExecutor.submit(new Callable<String>() {
            @Override
            public String call() {
                return llmProvider.analyzeAggregatedAlerts(aggregatedJson);
            }
        });

        try {
            return future.get(remainMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            future.cancel(true);
            log.warn("LLM invocation timed out after {} ms", remainMs);
            return null;
        } catch (InterruptedException ie) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException ee) {
            log.error("LLM invocation failed: {}", ee.getMessage());
            return null;
        }
    }

    private boolean isBudgetExceeded(long startMs) {
        return System.currentTimeMillis() - startMs > analysisTimeoutMs;
    }

    private String applyInputBudget(String aggregatedJson) {
        try {
            ObjectNode root = (ObjectNode) OBJECT_MAPPER.readTree(aggregatedJson);
            JsonNode alertsNode = root.get("aggregated_alerts");
            if (alertsNode != null && alertsNode.isArray()) {
                List<ObjectNode> alerts = new ArrayList<ObjectNode>();
                for (JsonNode node : alertsNode) {
                    if (node.isObject()) {
                        alerts.add((ObjectNode) node);
                    }
                }
                Collections.sort(alerts, new Comparator<ObjectNode>() {
                    @Override
                    public int compare(ObjectNode a, ObjectNode b) {
                        int ar = a.has("risk_score") ? a.get("risk_score").asInt(0) : 0;
                        int br = b.has("risk_score") ? b.get("risk_score").asInt(0) : 0;
                        return Integer.compare(br, ar);
                    }
                });

                ArrayNode limited = OBJECT_MAPPER.createArrayNode();
                int maxIps = Math.min(maxIpsPerAnalysis, alerts.size());
                for (int i = 0; i < maxIps; i++) {
                    limited.add(limitPerIpData(alerts.get(i).deepCopy()));
                }
                root.set("aggregated_alerts", limited);
            }
            String json = OBJECT_MAPPER.writeValueAsString(root);
            return json.length() > maxPromptChars ? json.substring(0, maxPromptChars) : json;
        } catch (Exception e) {
            log.warn("Failed to apply input budget: {}", e.getMessage());
            return aggregatedJson.length() > maxPromptChars ? aggregatedJson.substring(0, maxPromptChars) : aggregatedJson;
        }
    }

    private ObjectNode limitPerIpData(ObjectNode ipNode) {
        trimArray(ipNode, "top_payloads", maxEventsPerIp);
        trimArray(ipNode, "attack_chains", maxEventsPerIp);
        trimArray(ipNode, "target_urls", maxEventsPerIp);
        trimArray(ipNode, "user_agents", maxEventsPerIp);
        trimArray(ipNode, "http_methods", maxEventsPerIp);
        trimArray(ipNode, "param_names", maxEventsPerIp);
        trimArray(ipNode, "error_samples", Math.min(maxEventsPerIp, 10));
        return ipNode;
    }

    private void trimArray(ObjectNode node, String field, int maxSize) {
        JsonNode value = node.get(field);
        if (value != null && value.isArray() && value.size() > maxSize) {
            ArrayNode out = OBJECT_MAPPER.createArrayNode();
            for (int i = 0; i < maxSize; i++) {
                out.add(value.get(i));
            }
            node.set(field, out);
        }
    }

    private boolean validateLlmOutput(String llmResponse) {
        if (llmResponse == null) {
            return false;
        }
        String clean = llmResponse.trim();
        if (clean.length() < 60) {
            return false;
        }
        boolean hasSummary =
            clean.contains("执行摘要") || clean.contains("摘要") || clean.contains("风险") ||
                clean.toLowerCase().contains("summary") || clean.toLowerCase().contains("risk");
        boolean hasDefense =
            clean.contains("防御建议") || clean.contains("建议") || clean.contains("处置") ||
                clean.toLowerCase().contains("actionable defenses") || clean.toLowerCase().contains("recommend");
        boolean hasStructure = clean.contains("###") || clean.contains("##");
        return (hasSummary && hasDefense) || (hasStructure && hasDefense);
    }

    private List<String> readAlertLogs(File logFile) throws IOException {
        List<String> logs = new ArrayList<String>();
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                try {
                    OBJECT_MAPPER.readTree(trimmed);
                    logs.add(trimmed);
                } catch (Exception parseEx) {
                    log.warn("Skipping invalid JSON line: {}", trimmed.substring(0, Math.min(80, trimmed.length())));
                }
            }
        }
        return logs;
    }

    private AnalysisReport parseLlmResponse(String llmResponse, int alertCount) {
        AnalysisReport report = new AnalysisReport();
        report.setReportId("rpt_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
        report.setAlertCount(alertCount);
        report.setRawResponse(llmResponse);
        report.setStatus("success");
        report.setSummary(extractSummary(llmResponse));
        report.setAttackNarrative(normalizeNarrative(llmResponse));
        report.setAttackDetected(detectAttackInResponse(llmResponse));
        report.setConfidence(calculateConfidence(llmResponse));
        report.setRecommendations(extractRecommendations(llmResponse));
        report.setKeyIndicators(extractKeyIndicators(llmResponse));
        report.setAttackerSkillLevel(extractSkillLevel(llmResponse));
        report.setAutomationType(extractAutomation(llmResponse));
        report.setAttackerIntent(extractIntent(llmResponse));
        return report;
    }

    private AnalysisReport createLocalFallbackReport(AlertAggregator.AggregationResult aggregationResult, String reason, int alertCount) {
        AnalysisReport report = new AnalysisReport();
        report.setReportId("rpt_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
        report.setStatus("degraded");
        report.setAlertCount(alertCount);
        report.setErrorMessage(mapFallbackReason(reason));

        List<AggregatedAlert> alerts = aggregationResult.getAggregatedAlerts();
        int high = 0;
        int medium = 0;
        int low = 0;
        int maxRisk = 0;
        String maxRiskIp = "unknown";
        List<String> indicators = new ArrayList<String>();

        for (AggregatedAlert alert : alerts) {
            int risk = alert.getRiskScore();
            if (risk >= 70) {
                high++;
            } else if (risk >= 40) {
                medium++;
            } else {
                low++;
            }
            if (risk > maxRisk) {
                maxRisk = risk;
                maxRiskIp = alert.getIp();
            }
            if (alert.getIp() != null && indicators.size() < 5) {
                indicators.add(alert.getIp());
            }
            for (String attackType : alert.getAttackTypes().keySet()) {
                if (indicators.size() >= 10) {
                    break;
                }
                if (!indicators.contains(attackType)) {
                    indicators.add(attackType);
                }
            }
        }

        report.setRiskScore(maxRisk);
        report.setRiskLevel(maxRisk >= 70 ? "high" : (maxRisk >= 40 ? "medium" : "low"));
        report.setAttackDetected(maxRisk >= 40);
        report.setConfidence(0.65);
        report.setClassification(maxRisk >= 40 ? "potential_attack" : "likely_scanning");
        report.setAttackerSkillLevel("intermediate");
        report.setAutomationType("semi_auto");
        report.setAttackerIntent(maxRisk >= 70 ? "exploitation" : "reconnaissance");
        report.setKeyIndicators(indicators);

        report.setSummary("降级本地分析：涉及IP " + aggregationResult.getTotalIps() +
            " 个，高危 " + high + " 个，中危 " + medium + " 个，低危 " + low +
            " 个，最高风险IP " + maxRiskIp + "。原因：" + mapFallbackReason(reason));
        report.setAttackNarrative(buildFallbackNarrative(aggregationResult, reason, high, medium, low));
        report.setRecommendations(buildFallbackRecommendations(maxRiskIp, maxRisk));
        return report;
    }

    private String buildFallbackNarrative(AlertAggregator.AggregationResult aggregationResult, String reason, int high, int medium, int low) {
        return "本报告由本地降级策略生成。\n" +
            "降级原因：" + mapFallbackReason(reason) + "\n" +
            "总IP数：" + aggregationResult.getTotalIps() + "\n" +
            "总会话数：" + aggregationResult.getTotalSessions() + "\n" +
            "总事件数：" + aggregationResult.getTotalEvents() + "\n" +
            "风险分布：高危=" + high + "，中危=" + medium + "，低危=" + low + "\n" +
            "建议优先处置高风险IP并复核关键业务接口防护策略。";
    }

    private List<String> buildFallbackRecommendations(String topRiskIp, int maxRisk) {
        List<String> recommendations = new ArrayList<String>();
        if (topRiskIp != null && !"unknown".equals(topRiskIp)) {
            recommendations.add("[BLOCK] 在边界防护/WAF临时封禁高风险IP: " + topRiskIp);
        }
        recommendations.add("[MONITOR] 提升敏感接口及4xx/5xx异常峰值监控等级");
        recommendations.add("[REVIEW] 复核最近发布变更并加固输入校验与鉴权");
        if (maxRisk >= 70) {
            recommendations.add("[IR] 对高风险攻击活动启动应急分级处置");
        }
        return recommendations;
    }

    private String extractSummary(String response) {
        String target = extractSection(
            response,
            new String[]{"### 执行摘要", "## 执行摘要", "### Executive Summary", "## Executive Summary"},
            new String[]{"### 攻击活动画像", "## 攻击活动画像", "### 攻击者画像", "## 攻击者画像", "### Activity Profile", "## Activity Profile", "### Attacker Profile", "## Attacker Profile", "### 防御建议", "## 防御建议"}
        );
        if (target == null || target.trim().isEmpty()) {
            target = response;
        }
        String[] lines = target.split("\n");
        StringBuilder summary = new StringBuilder();
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("```")) {
                continue;
            }
            if (summary.length() > 0) {
                summary.append(' ');
            }
            summary.append(trimmed);
            if (summary.length() >= 280) {
                break;
            }
        }
        String out = summary.toString().trim();
        if (out.length() > 300) {
            out = out.substring(0, 300);
        }
        return out.isEmpty() ? "分析完成。" : out;
    }

    private boolean detectAttackInResponse(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("no attack") || lower.contains("false positive") || response.contains("非攻击")) {
            return false;
        }
        return lower.contains("attack") || lower.contains("exploit") || lower.contains("malicious")
            || response.contains("攻击") || response.contains("利用");
    }

    private double calculateConfidence(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("high confidence") || lower.contains("confirmed") || response.contains("高置信")) {
            return 0.9;
        }
        if (lower.contains("likely") || response.contains("较大概率")) {
            return 0.75;
        }
        if (lower.contains("possible") || lower.contains("uncertain") || response.contains("可能")) {
            return 0.55;
        }
        return 0.7;
    }

    private List<String> extractRecommendations(String response) {
        List<String> recommendations = new ArrayList<String>();
        String defenseSection = extractSection(
            response,
            new String[]{"### 防御建议", "## 防御建议", "### Actionable Defenses", "## Actionable Defenses"},
            new String[]{"### 统计口径说明", "## 统计口径说明", "### 攻击活动画像", "## 攻击活动画像", "### 攻击者画像", "## 攻击者画像", "### Activity Profile", "## Activity Profile", "### Attacker Profile"}
        );
        String source = (defenseSection == null || defenseSection.trim().isEmpty()) ? response : defenseSection;
        LinkedHashSet<String> dedup = new LinkedHashSet<String>();
        for (String line : source.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("-") || trimmed.startsWith("*") || trimmed.matches("^\\d+\\..*")) {
                String rec = trimmed.replaceAll("^[\\-\\*\\d\\.\\s]+", "").trim();
                if (rec.length() >= 6) {
                    dedup.add(rec);
                }
            } else if (trimmed.length() >= 12 && !trimmed.startsWith("#") && !trimmed.startsWith("```")) {
                dedup.add(trimmed);
            }
            if (dedup.size() >= 8) {
                break;
            }
        }
        recommendations.addAll(dedup);
        if (recommendations.isEmpty()) {
            recommendations.add("优先封禁高风险IP并提升关键接口监控等级。");
        }
        return recommendations;
    }

    private String normalizeNarrative(String response) {
        LinkedHashSet<String> unique = new LinkedHashSet<String>();
        StringBuilder out = new StringBuilder();
        for (String line : response.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (unique.add(trimmed)) {
                out.append(line).append('\n');
            }
        }
        return out.toString().trim();
    }

    private String extractSection(String text, String[] starts, String[] ends) {
        if (text == null) {
            return null;
        }
        int start = -1;
        for (String marker : starts) {
            int idx = text.indexOf(marker);
            if (idx >= 0 && (start < 0 || idx < start)) {
                start = idx + marker.length();
            }
        }
        if (start < 0) {
            return null;
        }
        int end = text.length();
        for (String marker : ends) {
            int idx = text.indexOf(marker, start);
            if (idx >= 0 && idx < end) {
                end = idx;
            }
        }
        return text.substring(start, end).trim();
    }

    private String mapFallbackReason(String reason) {
        if (reason == null) {
            return "未知原因";
        }
        if ("LLM output validation failed".equals(reason)) {
            return "LLM输出未通过结构校验";
        }
        if ("LLM returned empty response".equals(reason)) {
            return "LLM返回空内容";
        }
        if ("Analysis timeout before LLM invocation".equals(reason)) {
            return "分析在调用LLM前超时";
        }
        if ("Analysis timeout after input budgeting".equals(reason)) {
            return "分析在输入预算处理后超时";
        }
        return reason;
    }

    private List<String> extractKeyIndicators(String response) {
        List<String> indicators = new ArrayList<String>();
        Matcher matcher = IP_PATTERN.matcher(response);
        while (matcher.find() && indicators.size() < 10) {
            String ip = matcher.group();
            if (!indicators.contains(ip)) {
                indicators.add(ip);
            }
        }
        return indicators;
    }

    private String extractSkillLevel(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("advanced") || response.contains("高级")) {
            return "advanced";
        }
        if (lower.contains("novice") || lower.contains("script kiddie") || response.contains("初级")) {
            return "novice";
        }
        return "intermediate";
    }

    private String extractAutomation(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("fully automated") || response.contains("全自动")) {
            return "fully_auto";
        }
        if (lower.contains("manual") || response.contains("手动")) {
            return "manual";
        }
        return "semi_auto";
    }

    private String extractIntent(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("exfiltration") || response.contains("窃取")) {
            return "exfiltration";
        }
        if (lower.contains("recon") || response.contains("侦察")) {
            return "reconnaissance";
        }
        return "exploitation";
    }

    private AnalysisReport createErrorReport(String errorMessage, int alertCount) {
        AnalysisReport report = new AnalysisReport();
        report.setReportId("rpt_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
        report.setStatus("error");
        report.setAlertCount(alertCount);
        report.setErrorMessage(errorMessage);
        report.setRiskLevel("unknown");
        report.setRiskScore(0);
        report.setSummary("Analysis failed: " + errorMessage);
        report.setRecommendations(new ArrayList<String>());
        report.setAttackTypes(new ArrayList<AnalysisReport.AttackType>());
        report.setTimeline(new ArrayList<AnalysisReport.TimelineEvent>());
        report.setAffectedAssets(new ArrayList<String>());
        return report;
    }

    private void applyRiskFallbackFromAggregation(AnalysisReport report, AlertAggregator.AggregationResult aggregationResult) {
        if (report == null || aggregationResult == null || aggregationResult.getAggregatedAlerts() == null) {
            return;
        }

        int maxRisk = 0;
        for (AggregatedAlert alert : aggregationResult.getAggregatedAlerts()) {
            if (alert != null) {
                maxRisk = Math.max(maxRisk, alert.getRiskScore());
            }
        }

        boolean needScore = report.getRiskScore() <= 0;
        boolean needLevel = report.getRiskLevel() == null ||
            report.getRiskLevel().trim().isEmpty() ||
            "unknown".equalsIgnoreCase(report.getRiskLevel());

        if (needScore) {
            report.setRiskScore(maxRisk);
        }
        if (needLevel) {
            if (maxRisk >= 70) {
                report.setRiskLevel("high");
            } else if (maxRisk >= 40) {
                report.setRiskLevel("medium");
            } else {
                report.setRiskLevel("low");
            }
        }
    }

    public LlmProvider getLlmProvider() {
        return llmProvider;
    }

    public ConcurrentHashMap<String, AnalysisReport> getReportCache() {
        return reportCache;
    }

    public AnalysisReport getReport(String reportId) {
        return reportCache.get(reportId);
    }

    public List<AnalysisReport> getAllReports() {
        return new ArrayList<AnalysisReport>(reportCache.values());
    }

    public boolean isLogFileExists() {
        File logFile = new File(alertLogPath);
        return logFile.exists() && logFile.length() > 0;
    }
}
