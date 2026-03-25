package org.example.input_security_starter.llm.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.example.input_security_starter.llm.ip.AbuseIpDbClient;
import org.example.input_security_starter.llm.ip.IpQueryService;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.notification.feishu.FeishuNotifier;
import org.example.input_security_starter.notification.wecom.WeComNotifier;
import org.example.input_security_starter.notification.dingtalk.DingTalkNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    private static final int DEFAULT_MAX_ALERTS_PER_ANALYSIS = 50;
    private static final int DEFAULT_MAX_PROMPT_CHARS = 24_000;
    private static final int DEFAULT_MAX_IPS_PER_ANALYSIS = 50;
    private static final int DEFAULT_MAX_EVENTS_PER_IP = 50;
    private static final int HIGH_RISK_THRESHOLD = 80;
    private static final int MEDIUM_RISK_THRESHOLD = 50;
    private static final long DEFAULT_ANALYSIS_TIMEOUT_MS = 90_000L;
    private static final String[] SUMMARY_SECTION_START_MARKERS = new String[]{
        "### \u6267\u884c\u6458\u8981",
        "## \u6267\u884c\u6458\u8981",
        "### Executive Summary",
        "## Executive Summary"
    };
    private static final String[] SUMMARY_SECTION_END_MARKERS = new String[]{
        "### \u653b\u51fb\u6d3b\u52a8\u753b\u50cf",
        "## \u653b\u51fb\u6d3b\u52a8\u753b\u50cf",
        "### \u653b\u51fb\u8005\u753b\u50cf",
        "## \u653b\u51fb\u8005\u753b\u50cf",
        "### Activity Profile",
        "## Activity Profile",
        "### Attacker Profile",
        "## Attacker Profile",
        "### \u9632\u5fa1\u5efa\u8bae",
        "## \u9632\u5fa1\u5efa\u8bae"
    };
    private static final String[] DEFENSE_SECTION_START_MARKERS = new String[]{
        "### \u9632\u5fa1\u5efa\u8bae",
        "## \u9632\u5fa1\u5efa\u8bae",
        "### Actionable Defenses",
        "## Actionable Defenses"
    };
    private static final String[] DEFENSE_SECTION_END_MARKERS = new String[]{
        "### \u7edf\u8ba1\u53e3\u5f84\u8bf4\u660e",
        "## \u7edf\u8ba1\u53e3\u5f84\u8bf4\u660e",
        "### \u653b\u51fb\u6d3b\u52a8\u753b\u50cf",
        "## \u653b\u51fb\u6d3b\u52a8\u753b\u50cf",
        "### \u653b\u51fb\u8005\u753b\u50cf",
        "## \u653b\u51fb\u8005\u753b\u50cf",
        "### Activity Profile",
        "## Activity Profile",
        "### Attacker Profile",
        "## Attacker Profile"
    };

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
    private final WeComNotifier weComNotifier;
    private final DingTalkNotifier dingTalkNotifier;
    private final AtomicBoolean analysisInProgress;
    private final ExecutorService llmExecutor;

    public LlmAnalysisService(LlmProvider llmProvider, AbuseIpDbClient abuseIpDbClient, IpQueryService ipQueryService, String alertLogPath) {
        this(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            DEFAULT_MAX_ALERTS_PER_ANALYSIS,
            DEFAULT_MAX_PROMPT_CHARS,
            null,
            null,
            null
        );
    }

    public LlmAnalysisService(LlmProvider llmProvider, AbuseIpDbClient abuseIpDbClient, IpQueryService ipQueryService, String alertLogPath, int maxAlertsPerAnalysis) {
        this(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            maxAlertsPerAnalysis,
            DEFAULT_MAX_PROMPT_CHARS,
            null,
            null,
            null
        );
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
            DEFAULT_MAX_PROMPT_CHARS,
            feishuNotifier,
            null,
            null
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
        this(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            maxAlertsPerAnalysis,
            maxPromptChars,
            maxIpsPerAnalysis,
            maxEventsPerIp,
            analysisTimeoutMs,
            feishuNotifier,
            null
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
        FeishuNotifier feishuNotifier,
        WeComNotifier weComNotifier
    ) {
        this(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            maxAlertsPerAnalysis,
            maxPromptChars,
            maxIpsPerAnalysis,
            maxEventsPerIp,
            analysisTimeoutMs,
            feishuNotifier,
            weComNotifier,
            null
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
        FeishuNotifier feishuNotifier,
        WeComNotifier weComNotifier,
        DingTalkNotifier dingTalkNotifier
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
        this.weComNotifier = weComNotifier;
        this.dingTalkNotifier = dingTalkNotifier;
        this.reportCache = new ConcurrentHashMap<String, AnalysisReport>();
        this.analysisInProgress = new AtomicBoolean(false);
        this.llmExecutor = Executors.newCachedThreadPool();
    }

    public LlmAnalysisService(
        LlmProvider llmProvider,
        AbuseIpDbClient abuseIpDbClient,
        IpQueryService ipQueryService,
        String alertLogPath,
        int maxAlertsPerAnalysis,
        int maxPromptChars,
        FeishuNotifier feishuNotifier,
        WeComNotifier weComNotifier,
        DingTalkNotifier dingTalkNotifier
    ) {
        this(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            maxAlertsPerAnalysis,
            maxPromptChars,
            DEFAULT_MAX_IPS_PER_ANALYSIS,
            DEFAULT_MAX_EVENTS_PER_IP,
            DEFAULT_ANALYSIS_TIMEOUT_MS,
            feishuNotifier,
            weComNotifier,
            dingTalkNotifier
        );
    }

    public LlmAnalysisService(
        LlmProvider llmProvider,
        AbuseIpDbClient abuseIpDbClient,
        IpQueryService ipQueryService,
        String alertLogPath,
        int maxAlertsPerAnalysis,
        int maxPromptChars,
        FeishuNotifier feishuNotifier,
        WeComNotifier weComNotifier
    ) {
        this(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            maxAlertsPerAnalysis,
            maxPromptChars,
            DEFAULT_MAX_IPS_PER_ANALYSIS,
            DEFAULT_MAX_EVENTS_PER_IP,
            DEFAULT_ANALYSIS_TIMEOUT_MS,
            feishuNotifier,
            weComNotifier,
            null
        );
    }

    public LlmAnalysisService(LlmProvider llmProvider, AbuseIpDbClient abuseIpDbClient, String alertLogPath) {
        this(
            llmProvider,
            abuseIpDbClient,
            null,
            alertLogPath,
            DEFAULT_MAX_ALERTS_PER_ANALYSIS,
            DEFAULT_MAX_PROMPT_CHARS,
            null,
            null,
            null
        );
    }

    public AnalysisReport analyzeAttackChainAlerts() {
        return analyzeAttackChainAlerts(true);
    }

    public AnalysisReport analyzeAttackChainAlerts(boolean notifyNotifications) {
        IncrementalAnalysisResult result = analyzeAttackChainAlertsIncremental(0L, notifyNotifications);
        return result != null ? result.getReport() : null;
    }

    public IncrementalAnalysisResult analyzeAttackChainAlertsIncremental(long lastProcessedLine, boolean notifyNotifications) {
        if (!analysisInProgress.compareAndSet(false, true)) {
            return IncrementalAnalysisResult.error(createErrorReport("\u5206\u6790\u4efb\u52a1\u6b63\u5728\u8fdb\u884c\u4e2d", 0));
        }

        long startMs = System.currentTimeMillis();
        try {
            File logFile = new File(alertLogPath);
            if (!logFile.exists() || logFile.length() == 0) {
                log.info("Attack chain alert log is unavailable or empty: {}", alertLogPath);
                return IncrementalAnalysisResult.noNewAlerts(lastProcessedLine);
            }

            IncrementalAlertReadResult readResult = readNewAlertLogs(logFile, lastProcessedLine);
            if (!readResult.hasNewAlerts()) {
                log.info("No new alert logs found after line {} in file: {}", lastProcessedLine, alertLogPath);
                return IncrementalAnalysisResult.noNewAlerts(readResult.getEndLineInclusive());
            }

            List<String> alertLogs = readResult.getAlertLogs();
            if (alertLogs.isEmpty()) {
                log.info("No valid new alert logs found after line {} in file: {}", lastProcessedLine, alertLogPath);
                return IncrementalAnalysisResult.noNewAlerts(readResult.getEndLineInclusive());
            }

            AlertAggregator aggregator = new AlertAggregator(ipQueryService, maxAlertsPerAnalysis);
            AlertAggregator.AggregationResult aggregationResult = aggregator.aggregate(alertLogs);

            if (isBudgetExceeded(startMs)) {
                AnalysisReport report = createLocalFallbackReport(
                    aggregationResult,
                    "Analysis timeout before LLM invocation",
                    alertLogs.size()
                );
                return IncrementalAnalysisResult.withReport(report, readResult.getEndLineInclusive(), alertLogs.size());
            }

            String aggregatedJson = OBJECT_MAPPER.writeValueAsString(aggregationResult.toMap());
            String budgetedJson = applyInputBudget(aggregatedJson);

            if (isBudgetExceeded(startMs)) {
                AnalysisReport report = createLocalFallbackReport(
                    aggregationResult,
                    "Analysis timeout after input budgeting",
                    alertLogs.size()
                );
                return IncrementalAnalysisResult.withReport(report, readResult.getEndLineInclusive(), alertLogs.size());
            }

            LlmInvocationResult invocationResult = callLlmWithTimeout(budgetedJson, startMs);
            String llmResponse = invocationResult.getResponse();
            AnalysisReport report;
            if (llmResponse == null || llmResponse.trim().isEmpty()) {
                report = createLocalFallbackReport(
                    aggregationResult,
                    resolveFallbackReason(invocationResult),
                    aggregationResult.getProcessedAlerts()
                );
            } else if (!validateLlmOutput(llmResponse)) {
                report = createLocalFallbackReport(aggregationResult, "LLM output validation failed", aggregationResult.getProcessedAlerts());
            } else {
                report = parseLlmResponse(llmResponse, aggregationResult.getProcessedAlerts(), aggregationResult);
            }

            applyRiskFallbackFromAggregation(report, aggregationResult);
            applyConfidenceFallbackFromAggregation(report, aggregationResult);
            normalizeReportToChinese(report);
            enrichReportWithAggregationContext(report, aggregationResult);
            applyRecommendationQualityGuard(report, aggregationResult);
            appendDegradedReasonToSummary(report);
            report.setIpIntelligenceCount(aggregationResult.getTotalIps());
            report.setAlertCount(aggregationResult.getProcessedAlerts());
            reportCache.put(report.getReportId(), report);

            if (notifyNotifications) {
                sendEnabledNotifications(report);
            }
            return IncrementalAnalysisResult.withReport(report, readResult.getEndLineInclusive(), alertLogs.size());
        } catch (Exception e) {
            log.error("Failed to analyze attack chain alerts: {}", e.getMessage(), e);
            return IncrementalAnalysisResult.error(createErrorReport(e.getMessage(), 0));
        } finally {
            analysisInProgress.set(false);
        }
    }

    private LlmInvocationResult callLlmWithTimeout(final String aggregatedJson, long startMs) {
        long remainMs = analysisTimeoutMs - (System.currentTimeMillis() - startMs);
        if (remainMs <= 0) {
            return LlmInvocationResult.failure("analysis_timeout_before_llm_invocation");
        }

        Future<String> future = llmExecutor.submit(new Callable<String>() {
            @Override
            public String call() {
                return llmProvider.analyzeAggregatedAlerts(aggregatedJson);
            }
        });

        try {
            String response = future.get(remainMs, TimeUnit.MILLISECONDS);
            if (response != null && !response.trim().isEmpty()) {
                return LlmInvocationResult.success(response);
            }
            String providerReason = llmProvider.getLastFailureReason();
            if (!isNotBlank(providerReason)) {
                providerReason = "llm_empty_response";
            }
            return LlmInvocationResult.failure(providerReason);
        } catch (TimeoutException te) {
            future.cancel(true);
            log.warn("LLM invocation timed out after {} ms", remainMs);
            return LlmInvocationResult.failure("llm_invocation_timeout");
        } catch (InterruptedException ie) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return LlmInvocationResult.failure("llm_invocation_interrupted");
        } catch (ExecutionException ee) {
            log.error("LLM invocation failed: {}", ee.getMessage());
            String providerReason = llmProvider.getLastFailureReason();
            if (!isNotBlank(providerReason)) {
                providerReason = "llm_execution_exception";
            }
            return LlmInvocationResult.failure(providerReason);
        }
    }

    private String resolveFallbackReason(LlmInvocationResult invocationResult) {
        if (invocationResult == null || !isNotBlank(invocationResult.getFailureReason())) {
            return "LLM returned empty response";
        }
        return invocationResult.getFailureReason();
    }

    private void appendDegradedReasonToSummary(AnalysisReport report) {
        if (report == null || !"degraded".equalsIgnoreCase(report.getStatus()) || !isNotBlank(report.getErrorMessage())) {
            return;
        }
        String readableReason = mapFallbackReason(report.getErrorMessage());
        if (!isNotBlank(readableReason)) {
            return;
        }
        String summary = report.getSummary();
        if (!isNotBlank(summary)) {
            report.setSummary("降级原因：" + readableReason);
            return;
        }
        if (!summary.contains(readableReason) && !summary.contains("降级原因")) {
            report.setSummary(summary + " 降级原因：" + readableReason + "。");
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
        JsonNode jsonNode = tryParseResponseJson(clean);
        if (jsonNode != null && jsonNode.isObject()) {
            boolean hasSummaryField = jsonNode.has("summary");
            boolean hasRecommendationField = jsonNode.has("recommendations");
            boolean hasNarrativeField = jsonNode.has("attack_narrative");
            boolean hasVerdictField = jsonNode.has("verdict");
            if (hasSummaryField && hasRecommendationField && (hasNarrativeField || hasVerdictField)) {
                return true;
            }
        }
        boolean hasSummary =
            clean.contains("\u6267\u884c\u6458\u8981") || clean.contains("\u6458\u8981") || clean.contains("\u98ce\u9669") ||
                clean.toLowerCase().contains("summary") || clean.toLowerCase().contains("risk");
        boolean hasDefense =
            clean.contains("\u9632\u5fa1\u5efa\u8bae") || clean.contains("\u5efa\u8bae") || clean.contains("\u5904\u7f6e") ||
                clean.toLowerCase().contains("actionable defenses") || clean.toLowerCase().contains("recommend");
        boolean hasStructure = clean.contains("###") || clean.contains("##");
        return (hasSummary && hasDefense) || (hasStructure && hasDefense);
    }

    private IncrementalAlertReadResult readNewAlertLogs(File logFile, long lastProcessedLine) throws IOException {
        List<String> logs = new ArrayList<String>();
        long currentLine = 0L;
        long effectiveLastProcessedLine = Math.max(0L, lastProcessedLine);

        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                currentLine++;
                if (currentLine <= effectiveLastProcessedLine) {
                    continue;
                }

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

        return new IncrementalAlertReadResult(
            logs,
            effectiveLastProcessedLine,
            currentLine,
            currentLine > effectiveLastProcessedLine
        );
    }

    private AnalysisReport parseLlmResponse(
        String llmResponse,
        int alertCount,
        AlertAggregator.AggregationResult aggregationResult
    ) {
        AnalysisReport report = new AnalysisReport();
        report.setReportId("rpt_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
        report.setAlertCount(alertCount);
        report.setRawResponse(llmResponse);
        report.setStatus("success");
        if (!populateReportFromStructuredJson(report, llmResponse)) {
            report.setSummary(extractSummary(llmResponse));
            report.setAttackNarrative(normalizeNarrative(llmResponse));
            report.setAttackDetected(detectAttackInResponse(llmResponse));
            report.setConfidence(calculateConfidence(llmResponse));
            report.setRecommendations(extractRecommendations(llmResponse));
            report.setKeyIndicators(extractKeyIndicators(llmResponse));
            report.setAttackerSkillLevel(extractSkillLevel(llmResponse));
            report.setAutomationType(extractAutomation(llmResponse));
            report.setAttackerIntent(extractIntent(llmResponse));
        }
        if (aggregationResult != null) {
            int maxRisk = findMaxRiskScore(aggregationResult.getAggregatedAlerts());
            if (report.getRiskScore() <= 0 && maxRisk > 0) {
                report.setRiskScore(maxRisk);
            }
        }
        return report;
    }

    private boolean populateReportFromStructuredJson(AnalysisReport report, String llmResponse) {
        JsonNode root = tryParseResponseJson(llmResponse);
        if (root == null || !root.isObject()) {
            return false;
        }

        boolean populated = false;
        String summary = readText(root, "summary");
        if (isNotBlank(summary)) {
            report.setSummary(summary);
            populated = true;
        }

        String narrative = readText(root, "attack_narrative");
        if (!isNotBlank(narrative) && root.has("evidence") && root.get("evidence").isObject()) {
            narrative = readText(root.get("evidence"), "attack_narrative");
        }
        if (isNotBlank(narrative)) {
            report.setAttackNarrative(normalizeNarrative(narrative));
            populated = true;
        }

        List<String> recommendations = readStringArray(root.get("recommendations"), 12);
        if (!recommendations.isEmpty()) {
            report.setRecommendations(recommendations);
            populated = true;
        }

        JsonNode verdictNode = root.get("verdict");
        if (verdictNode != null && verdictNode.isObject()) {
            report.setAttackDetected(readBoolean(verdictNode, "is_attack", detectAttackInResponse(llmResponse)));
            report.setConfidence(readDouble(verdictNode, "confidence", calculateConfidence(llmResponse)));
            String classification = readText(verdictNode, "classification");
            if (isNotBlank(classification)) {
                report.setClassification(classification);
            }
            populated = true;
        } else {
            report.setAttackDetected(detectAttackInResponse(llmResponse));
            report.setConfidence(calculateConfidence(llmResponse));
        }

        JsonNode attackerNode = root.get("attacker");
        if ((attackerNode == null || !attackerNode.isObject()) && root.has("attacker_profile") && root.get("attacker_profile").isObject()) {
            attackerNode = root.get("attacker_profile");
        }
        if (attackerNode != null && attackerNode.isObject()) {
            String skillLevel = readText(attackerNode, "skill_level");
            if (isNotBlank(skillLevel)) {
                report.setAttackerSkillLevel(skillLevel);
                populated = true;
            }
            String automation = readText(attackerNode, "automation");
            if (isNotBlank(automation)) {
                report.setAutomationType(automation);
                populated = true;
            }
            String intent = readText(attackerNode, "intent");
            if (isNotBlank(intent)) {
                report.setAttackerIntent(intent);
                populated = true;
            }
            String pattern = readText(attackerNode, "pattern");
            if (isNotBlank(pattern)) {
                report.setAttackerPattern(pattern);
                populated = true;
            }
            double intentConfidence = readDouble(attackerNode, "intent_confidence", -1.0);
            if (intentConfidence >= 0.0 && intentConfidence <= 1.0) {
                report.setAttackerIntentConfidence(intentConfidence);
                populated = true;
            }
        }

        if (report.getAttackerIntentConfidence() <= 0) {
            double topLevelIntentConfidence = readDouble(root, "intent_confidence", -1.0);
            if (topLevelIntentConfidence >= 0.0 && topLevelIntentConfidence <= 1.0) {
                report.setAttackerIntentConfidence(topLevelIntentConfidence);
                populated = true;
            }
        }

        List<AnalysisReport.PeerAttacker> peerAttackers = readPeerAttackers(root.get("peer_attackers"), 12);
        if (peerAttackers.isEmpty()) {
            peerAttackers = readPeerAttackers(root.get("related_attackers"), 12);
        }
        if (!peerAttackers.isEmpty()) {
            report.setPeerAttackers(peerAttackers);
            populated = true;
        }

        List<String> keyIndicators = readStringArray(root.get("key_indicators"), 10);
        if (keyIndicators.isEmpty() && root.has("evidence") && root.get("evidence").isObject()) {
            keyIndicators = readStringArray(root.get("evidence").get("key_indicators"), 10);
        }
        if (!keyIndicators.isEmpty()) {
            report.setKeyIndicators(keyIndicators);
            populated = true;
        } else {
            report.setKeyIndicators(extractKeyIndicators(llmResponse));
        }

        int riskScore = readInt(root, "risk_score", 0);
        if (riskScore > 0) {
            report.setRiskScore(riskScore);
            populated = true;
        }
        String riskLevel = readText(root, "risk_level");
        if (isNotBlank(riskLevel)) {
            report.setRiskLevel(riskLevel);
            populated = true;
        }

        return populated;
    }

    private JsonNode tryParseResponseJson(String llmResponse) {
        if (llmResponse == null) {
            return null;
        }
        String clean = llmResponse.trim();
        if (clean.isEmpty()) {
            return null;
        }
        if (clean.startsWith("```")) {
            int firstLineEnd = clean.indexOf('\n');
            int lastFence = clean.lastIndexOf("```");
            if (firstLineEnd > 0 && lastFence > firstLineEnd) {
                clean = clean.substring(firstLineEnd + 1, lastFence).trim();
            }
        }
        try {
            return OBJECT_MAPPER.readTree(clean);
        } catch (Exception ignored) {
            int start = clean.indexOf('{');
            int end = clean.lastIndexOf('}');
            if (start >= 0 && end > start) {
                try {
                    return OBJECT_MAPPER.readTree(clean.substring(start, end + 1));
                } catch (Exception ignoredAgain) {
                    return null;
                }
            }
            return null;
        }
    }

    private String readText(JsonNode node, String field) {
        if (node == null || field == null || !node.has(field) || node.get(field) == null || node.get(field).isNull()) {
            return null;
        }
        return node.get(field).asText();
    }

    private int readInt(JsonNode node, String field, int defaultValue) {
        if (node == null || !node.has(field) || node.get(field) == null || node.get(field).isNull()) {
            return defaultValue;
        }
        JsonNode value = node.get(field);
        if (value.isNumber()) {
            return value.asInt(defaultValue);
        }
        try {
            return Integer.parseInt(value.asText().trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private double readDouble(JsonNode node, String field, double defaultValue) {
        if (node == null || !node.has(field) || node.get(field) == null || node.get(field).isNull()) {
            return defaultValue;
        }
        JsonNode value = node.get(field);
        if (value.isNumber()) {
            return value.asDouble(defaultValue);
        }
        try {
            return Double.parseDouble(value.asText().trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private boolean readBoolean(JsonNode node, String field, boolean defaultValue) {
        if (node == null || !node.has(field) || node.get(field) == null || node.get(field).isNull()) {
            return defaultValue;
        }
        JsonNode value = node.get(field);
        if (value.isBoolean()) {
            return value.asBoolean(defaultValue);
        }
        String text = value.asText("").trim().toLowerCase();
        if ("true".equals(text) || "yes".equals(text) || "1".equals(text)) {
            return true;
        }
        if ("false".equals(text) || "no".equals(text) || "0".equals(text)) {
            return false;
        }
        return defaultValue;
    }

    private List<String> readStringArray(JsonNode node, int maxSize) {
        List<String> values = new ArrayList<String>();
        if (node == null) {
            return values;
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (values.size() >= maxSize) {
                    break;
                }
                if (item == null || item.isNull()) {
                    continue;
                }
                String text = item.asText();
                if (isNotBlank(text) && !values.contains(text.trim())) {
                    values.add(text.trim());
                }
            }
            return values;
        }
        String text = node.asText();
        if (isNotBlank(text)) {
            values.add(text.trim());
        }
        return values;
    }

    private List<AnalysisReport.PeerAttacker> readPeerAttackers(JsonNode node, int maxSize) {
        List<AnalysisReport.PeerAttacker> values = new ArrayList<AnalysisReport.PeerAttacker>();
        if (node == null || maxSize <= 0) {
            return values;
        }

        Set<String> seen = new LinkedHashSet<String>();
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (values.size() >= maxSize || item == null || item.isNull()) {
                    if (values.size() >= maxSize) {
                        break;
                    }
                    continue;
                }
                String ip = null;
                String relationship = null;
                double confidence = 0.0;
                String relatedToIp = null;
                if (item.isObject()) {
                    ip = readText(item, "ip");
                    if (!isNotBlank(ip)) {
                        ip = readText(item, "target_ip");
                    }
                    relationship = readText(item, "relationship");
                    if (!isNotBlank(relationship)) {
                        relationship = readText(item, "reason");
                    }
                    confidence = readDouble(item, "confidence", -1.0);
                    if (confidence < 0) {
                        confidence = readDouble(item, "similarity", 0.0);
                    }
                    relatedToIp = readText(item, "related_to");
                } else {
                    ip = item.asText();
                    relationship = "unknown";
                }

                if (!isNotBlank(ip)) {
                    continue;
                }
                String normalizedIp = ip.trim();
                String normalizedRelationship = isNotBlank(relationship) ? relationship.trim() : "unknown";
                double normalizedConfidence = Math.max(0.0, Math.min(1.0, confidence));
                String dedupeKey = normalizedIp + "|" + normalizedRelationship;
                if (seen.add(dedupeKey)) {
                    values.add(new AnalysisReport.PeerAttacker(normalizedIp, normalizedRelationship, normalizedConfidence, relatedToIp));
                }
            }
            return values;
        }

        String ip = node.asText();
        if (isNotBlank(ip)) {
            values.add(new AnalysisReport.PeerAttacker(ip.trim(), "unknown", 0.0));
        }
        return values;
    }

    private void normalizeReportToChinese(AnalysisReport report) {
        if (report == null) {
            return;
        }

        report.setSummary(normalizeSummaryToChinese(report));
        report.setAttackNarrative(normalizeNarrativeToChinese(report));
        report.setRecommendations(normalizeRecommendationsToChinese(report.getRecommendations()));

        if (!isNotBlank(report.getClassification())) {
            report.setClassification(report.isAttackDetected() ? "\u53ef\u7591\u653b\u51fb\u6d3b\u52a8" : "\u4f4e\u98ce\u9669\u63a2\u6d4b\u884c\u4e3a");
        } else {
            report.setClassification(normalizeClassificationToChinese(report.getClassification(), report.isAttackDetected()));
        }
        report.setAttackerSkillLevel(normalizeSkillLevelToChinese(report.getAttackerSkillLevel()));
        report.setAutomationType(normalizeAutomationToChinese(report.getAutomationType()));
        report.setAttackerIntent(normalizeIntentToChinese(report.getAttackerIntent()));
    }

    private String normalizeSummaryToChinese(AnalysisReport report) {
        String summary = report.getSummary();
        if (isNotBlank(summary) && containsChinese(summary)) {
            return summary.trim();
        }
        int confidence = (int) Math.round(Math.max(0.0, Math.min(1.0, report.getConfidence())) * 100.0);
        int indicatorCount = report.getKeyIndicators() == null ? 0 : report.getKeyIndicators().size();
        int recommendationCount = report.getRecommendations() == null ? 0 : report.getRecommendations().size();
        String attackText = report.isAttackDetected() ? "\u68c0\u6d4b\u5230\u653b\u51fb\u6d3b\u52a8" : "\u672a\u53d1\u73b0\u660e\u786e\u653b\u51fb\u6d3b\u52a8";
        return attackText + "\uff0c\u5f53\u524d\u7f6e\u4fe1\u5ea6\u7ea6" + confidence + "%\uff0c\u5df2\u63d0\u53d6\u5173\u952e\u6307\u6807" + indicatorCount +
            "\u9879\uff0c\u5e76\u751f\u6210\u5904\u7f6e\u5efa\u8bae" + recommendationCount + "\u6761\u3002";
    }

    private String normalizeNarrativeToChinese(AnalysisReport report) {
        String narrative = report.getAttackNarrative();
        if (isNotBlank(narrative) && containsChinese(narrative)) {
            return narrative.trim();
        }
        StringBuilder out = new StringBuilder();
        out.append("\u57fa\u4e8e\u805a\u5408\u544a\u8b66\u6570\u636e\uff0c\u5df2\u5b8c\u6210\u653b\u51fb\u94fe\u7814\u5224\u3002");
        out.append("\u5224\u5b9a\u7ed3\u679c\uff1a").append(report.isAttackDetected() ? "\u5b58\u5728\u653b\u51fb\u6d3b\u52a8\u3002" : "\u6682\u672a\u786e\u8ba4\u653b\u51fb\u6d3b\u52a8\u3002");
        out.append("\u6d3b\u52a8\u590d\u6742\u5ea6\uff1a").append(normalizeSkillLevelToChinese(report.getAttackerSkillLevel())).append("\uff1b");
        out.append("\u81ea\u52a8\u5316\u7a0b\u5ea6\uff1a").append(normalizeAutomationToChinese(report.getAutomationType())).append("\uff1b");
        out.append("\u4e3b\u8981\u610f\u56fe\uff1a").append(normalizeIntentToChinese(report.getAttackerIntent())).append("\u3002");
        if (report.getKeyIndicators() != null && !report.getKeyIndicators().isEmpty()) {
            out.append("\u5173\u952e\u6307\u6807\u5305\u62ec\uff1a");
            int limit = Math.min(5, report.getKeyIndicators().size());
            for (int i = 0; i < limit; i++) {
                if (i > 0) {
                    out.append("\u3001");
                }
                out.append(report.getKeyIndicators().get(i));
            }
            out.append("\u3002");
        }
        return out.toString();
    }

    private List<String> normalizeRecommendationsToChinese(List<String> recommendations) {
        LinkedHashSet<String> output = new LinkedHashSet<String>();
        if (recommendations != null) {
            for (String recommendation : recommendations) {
                String normalized = normalizeOneRecommendationToChinese(recommendation);
                if (isNotBlank(normalized)) {
                    output.add(normalized);
                }
                if (output.size() >= 8) {
                    break;
                }
            }
        }
        if (output.isEmpty()) {
            output.add("[BLOCK] \u7acb\u5373\u5c01\u7981\u9ad8\u98ce\u9669\u6765\u6e90IP\u5e76\u9650\u5236\u53ef\u7591\u8bbf\u95ee\u8def\u5f84");
            output.add("[MONITOR] \u63d0\u5347\u5173\u952e\u63a5\u53e3\u4e0e\u5f02\u5e38\u72b6\u6001\u7801\u7684\u5b9e\u65f6\u76d1\u63a7");
            output.add("[REVIEW] \u590d\u6838\u8f93\u5165\u6821\u9a8c\u3001\u9274\u6743\u4e0e\u53d1\u5e03\u53d8\u66f4\u8bb0\u5f55");
        }
        return new ArrayList<String>(output);
    }

    private String normalizeOneRecommendationToChinese(String recommendation) {
        if (!isNotBlank(recommendation)) {
            return null;
        }
        String clean = recommendation.trim().replaceAll("\\s+", " ");
        String upper = clean.toUpperCase();
        String tag = null;
        if (upper.startsWith("[BLOCK]")) {
            tag = "[BLOCK]";
        } else if (upper.startsWith("[PATCH]")) {
            tag = "[PATCH]";
        } else if (upper.startsWith("[MONITOR]")) {
            tag = "[MONITOR]";
        } else if (upper.startsWith("[REVIEW]")) {
            tag = "[REVIEW]";
        } else if (upper.startsWith("[IR]")) {
            tag = "[IR]";
        }

        if (containsChinese(clean)) {
            return clean;
        }

        if ("[BLOCK]".equals(tag)) {
            return "[BLOCK] \u7acb\u5373\u5c01\u7981\u9ad8\u98ce\u9669\u6765\u6e90IP\u5e76\u9650\u5236\u53ef\u7591\u8bbf\u95ee\u8def\u5f84";
        }
        if ("[PATCH]".equals(tag)) {
            return "[PATCH] \u5c3d\u5feb\u4fee\u590d\u66b4\u9732\u6f0f\u6d1e\u5e76\u5b8c\u6210\u8865\u4e01\u6709\u6548\u6027\u9a8c\u8bc1";
        }
        if ("[MONITOR]".equals(tag)) {
            return "[MONITOR] \u63d0\u5347\u6587\u4ef6\u4e0a\u4f20\u3001\u547d\u4ee4\u6267\u884c\u4e0e\u5f02\u5e38\u54cd\u5e94\u7684\u76d1\u63a7\u7b49\u7ea7";
        }
        if ("[REVIEW]".equals(tag)) {
            return "[REVIEW] \u590d\u6838\u76ee\u5f55\u904d\u5386\u4e0e\u9274\u6743\u7b56\u7565\uff0c\u6392\u67e5\u8bbf\u95ee\u63a7\u5236\u7f3a\u9677";
        }
        if ("[IR]".equals(tag)) {
            return "[IR] \u542f\u52a8\u5e94\u6025\u54cd\u5e94\u6d41\u7a0b\u5e76\u4fdd\u5168\u65e5\u5fd7\u4e0e\u53d6\u8bc1\u8bc1\u636e";
        }
        return "\u6267\u884c\u5206\u7ea7\u5904\u7f6e\u5e76\u6301\u7eed\u8ddf\u8e2a\u76f8\u5173\u653b\u51fb\u6307\u6807\u53d8\u5316";
    }

    private String normalizeClassificationToChinese(String classification, boolean isAttackDetected) {
        if (!isNotBlank(classification)) {
            return isAttackDetected ? "\u53ef\u7591\u653b\u51fb\u6d3b\u52a8" : "\u4f4e\u98ce\u9669\u63a2\u6d4b\u884c\u4e3a";
        }
        String text = classification.trim();
        if (containsChinese(text)) {
            return text;
        }
        String lower = text.toLowerCase();
        if (lower.contains("exploitation")) {
            return "\u6f0f\u6d1e\u5229\u7528\u653b\u51fb";
        }
        if (lower.contains("recon")) {
            return "\u4fa6\u5bdf\u63a2\u6d4b\u6d3b\u52a8";
        }
        if (lower.contains("exfiltration")) {
            return "\u6570\u636e\u7a83\u53d6\u6d3b\u52a8";
        }
        if (lower.contains("attack") || lower.contains("malicious")) {
            return "\u653b\u51fb\u6d3b\u52a8";
        }
        if (lower.contains("scan")) {
            return "\u626b\u63cf\u63a2\u6d4b\u6d3b\u52a8";
        }
        return isAttackDetected ? "\u53ef\u7591\u653b\u51fb\u6d3b\u52a8" : "\u4f4e\u98ce\u9669\u63a2\u6d4b\u884c\u4e3a";
    }

    private String normalizeSkillLevelToChinese(String skillLevel) {
        if (!isNotBlank(skillLevel)) {
            return "\u4e2d\u7ea7";
        }
        String text = skillLevel.trim();
        String lower = text.toLowerCase();
        if (text.contains("\u9ad8\u7ea7") || lower.contains("advanced")) {
            return "\u9ad8\u7ea7";
        }
        if (text.contains("\u521d\u7ea7") || lower.contains("novice") || lower.contains("script kiddie")) {
            return "\u521d\u7ea7";
        }
        if (text.contains("\u4e2d\u7ea7") || lower.contains("intermediate")) {
            return "\u4e2d\u7ea7";
        }
        return "\u4e2d\u7ea7";
    }

    private String normalizeAutomationToChinese(String automation) {
        if (!isNotBlank(automation)) {
            return "\u534a\u81ea\u52a8";
        }
        String text = automation.trim();
        String lower = text.toLowerCase();
        if (text.contains("\u5168\u81ea\u52a8") || lower.contains("fully_auto") || lower.contains("fully automated")) {
            return "\u5168\u81ea\u52a8";
        }
        if (text.contains("\u624b\u52a8") || lower.contains("manual")) {
            return "\u624b\u52a8";
        }
        if (text.contains("\u534a\u81ea\u52a8") || lower.contains("semi_auto")) {
            return "\u534a\u81ea\u52a8";
        }
        return "\u534a\u81ea\u52a8";
    }

    private String normalizeIntentToChinese(String intent) {
        if (!isNotBlank(intent)) {
            return "\u6f0f\u6d1e\u5229\u7528";
        }
        String text = intent.trim();
        String lower = text.toLowerCase();
        if (text.contains("\u4fa6\u5bdf") || lower.contains("recon")) {
            return "\u4fa6\u5bdf\u63a2\u6d4b";
        }
        if (text.contains("\u7a83\u53d6") || lower.contains("exfiltration")) {
            return "\u6570\u636e\u7a83\u53d6";
        }
        if (text.contains("\u6a2a\u5411") || lower.contains("lateral")) {
            return "\u6a2a\u5411\u79fb\u52a8";
        }
        if (text.contains("\u5229\u7528") || lower.contains("exploitation")) {
            return "\u6f0f\u6d1e\u5229\u7528";
        }
        return "\u6f0f\u6d1e\u5229\u7528";
    }

    private boolean containsChinese(String text) {
        if (text == null) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (ch >= '\u4e00' && ch <= '\u9fa5') {
                return true;
            }
        }
        return false;
    }

    private boolean isNotBlank(String text) {
        return text != null && !text.trim().isEmpty();
    }

    private void enrichReportWithAggregationContext(
        AnalysisReport report,
        AlertAggregator.AggregationResult aggregationResult
    ) {
        if (report == null || aggregationResult == null) {
            return;
        }

        List<AggregatedAlert> alerts = aggregationResult.getAggregatedAlerts();
        if (alerts == null) {
            alerts = Collections.emptyList();
        }

        int highRisk = 0;
        int mediumRisk = 0;
        int lowRisk = 0;
        int maxRisk = 0;
        LinkedHashSet<String> phaseSet = new LinkedHashSet<String>();
        Map<String, Integer> attackTypeCounter = new HashMap<String, Integer>();
        LinkedHashSet<String> targetUrlSet = new LinkedHashSet<String>();
        LinkedHashSet<String> publicIpSet = new LinkedHashSet<String>();
        LinkedHashSet<String> payloadSamples = new LinkedHashSet<String>();
        Map<Integer, Integer> statusCodeDistribution = new HashMap<Integer, Integer>();
        int successEvents = 0;
        int statusEvents = 0;
        List<AnalysisReport.SourceDetail> topSources = new ArrayList<AnalysisReport.SourceDetail>();

        for (AggregatedAlert alert : alerts) {
            if (alert == null) {
                continue;
            }
            int risk = alert.getRiskScore();
            maxRisk = Math.max(maxRisk, risk);
            if (risk >= HIGH_RISK_THRESHOLD) {
                highRisk++;
            } else if (risk >= MEDIUM_RISK_THRESHOLD) {
                mediumRisk++;
            } else {
                lowRisk++;
            }

            String ip = alert.getIp();
            if (isPublicRoutableIp(ip)) {
                publicIpSet.add(ip);
            }

            if (alert.getAttackPhases() != null) {
                phaseSet.addAll(alert.getAttackPhases());
            }
            if (alert.getAttackTypes() != null) {
                for (Map.Entry<String, Integer> entry : alert.getAttackTypes().entrySet()) {
                    String type = entry.getKey();
                    int count = entry.getValue() == null ? 0 : entry.getValue();
                    if (!isNotBlank(type) || count <= 0) {
                        continue;
                    }
                    attackTypeCounter.put(type, attackTypeCounter.getOrDefault(type, 0) + count);
                }
            }
            if (alert.getTargetUrls() != null) {
                for (String url : alert.getTargetUrls()) {
                    if (isNotBlank(url)) {
                        targetUrlSet.add(url.trim());
                    }
                    if (targetUrlSet.size() >= 12) {
                        break;
                    }
                }
            }
            if (alert.getTopPayloads() != null) {
                for (String payload : alert.getTopPayloads()) {
                    if (payloadSamples.size() >= 8) {
                        break;
                    }
                    String sanitized = sanitizePayloadSample(payload);
                    if (isNotBlank(sanitized)) {
                        payloadSamples.add(sanitized);
                    }
                }
            }
            if (alert.getStatusCodes() != null) {
                for (Map.Entry<Integer, Integer> statusEntry : alert.getStatusCodes().entrySet()) {
                    Integer code = statusEntry.getKey();
                    int count = statusEntry.getValue() == null ? 0 : statusEntry.getValue();
                    if (code == null || count <= 0 || !isStandardHttpStatusCode(code)) {
                        continue;
                    }
                    statusCodeDistribution.put(code, statusCodeDistribution.getOrDefault(code, 0) + count);
                    statusEvents += count;
                    if (code >= 200 && code < 300) {
                        successEvents += count;
                    }
                }
            }

            AnalysisReport.SourceDetail sourceDetail = new AnalysisReport.SourceDetail();
            sourceDetail.setIp(alert.getIp());
            sourceDetail.setRiskScore(alert.getRiskScore());
            sourceDetail.setPrimaryAttackType(pickPrimaryAttackType(alert.getAttackTypes()));
            sourceDetail.setSessionCount(alert.getSessionCount());
            sourceDetail.setTotalEvents(alert.getTotalEvents());
            int sourceEventTotal = alert.getSuccessCount() + alert.getFailureCount();
            if (sourceEventTotal > 0) {
                sourceDetail.setSuccessRate(Math.round((alert.getSuccessCount() * 10000.0) / sourceEventTotal) / 100.0);
            }
            sourceDetail.setAsn(alert.getAsn());
            sourceDetail.setCountry(alert.getCountry());
            sourceDetail.setIsp(alert.getIsp());
            sourceDetail.setThreatLevel(alert.getThreatLevel());
            sourceDetail.setProfileAttackCount(alert.getProfileAttackCount());
            sourceDetail.setFirstSeenTs(alert.getFirstSeenTs());
            sourceDetail.setLastSeenTs(alert.getLastSeenTs());
            topSources.add(sourceDetail);
        }

        List<String> topAttackTypes = pickTopAttackTypes(attackTypeCounter, 5);
        List<String> topTargetUrls = new ArrayList<String>();
        for (String url : targetUrlSet) {
            topTargetUrls.add(url);
            if (topTargetUrls.size() >= 5) {
                break;
            }
        }
        List<String> publicIps = new ArrayList<String>(publicIpSet);
        List<AnalysisReport.AttackType> attackTypes = buildAttackTypeViews(attackTypeCounter, maxRisk);
        if (!topSources.isEmpty()) {
            Collections.sort(topSources, new Comparator<AnalysisReport.SourceDetail>() {
                @Override
                public int compare(AnalysisReport.SourceDetail a, AnalysisReport.SourceDetail b) {
                    return Integer.compare(b.getRiskScore(), a.getRiskScore());
                }
            });
            if (topSources.size() > 8) {
                topSources = new ArrayList<AnalysisReport.SourceDetail>(topSources.subList(0, 8));
            }
        }

        report.setKeyIndicators(selectKeyIndicators(report.getKeyIndicators(), publicIps, topAttackTypes, topTargetUrls));
        report.setSummary(buildQuantifiedSummary(report, aggregationResult, highRisk, mediumRisk, lowRisk, maxRisk));
        report.setAttackNarrative(buildContextNarrative(report, phaseSet, topAttackTypes, topTargetUrls));
        report.setRecommendations(buildContextAwareRecommendations(report, topAttackTypes, topTargetUrls, publicIps, maxRisk));
        report.setAttackerSkillLevel(calibrateSkillLevel(phaseSet, topAttackTypes, maxRisk));
        report.setWindowStart(aggregationResult.getStartTime());
        report.setWindowEnd(aggregationResult.getEndTime());
        report.setOriginalAlertCount(aggregationResult.getOriginalAlerts());
        report.setTotalIps(aggregationResult.getTotalIps());
        report.setHighRiskIps(highRisk);
        report.setMediumRiskIps(mediumRisk);
        report.setLowRiskIps(lowRisk);
        report.setTopAttackTypes(topAttackTypes);
        report.setTopTargetUrls(topTargetUrls);
        report.setTopSources(topSources);
        if (!payloadSamples.isEmpty()) {
            report.setPayloadSamples(new ArrayList<String>(payloadSamples));
        }
        if (!statusCodeDistribution.isEmpty()) {
            report.setStatusCodeDistribution(statusCodeDistribution);
        }
        if (statusEvents > 0) {
            report.setOverallSuccessRate(Math.round((successEvents * 10000.0) / statusEvents) / 100.0);
        }
        if (report.getAttackTypes() == null || report.getAttackTypes().isEmpty()) {
            report.setAttackTypes(attackTypes);
        }
        if (report.getAffectedAssets() == null || report.getAffectedAssets().isEmpty()) {
            report.setAffectedAssets(new ArrayList<String>(topTargetUrls));
        }
        if (!topSources.isEmpty() && isNotBlank(topSources.get(0).getIp())) {
            report.setMainAttackerIp(topSources.get(0).getIp());
        }
        if ((report.getPeerAttackers() == null || report.getPeerAttackers().isEmpty())
            && aggregationResult.getAllPeerAttackers() != null
            && !aggregationResult.getAllPeerAttackers().isEmpty()) {
            report.setPeerAttackers(convertPeerAttackers(aggregationResult.getAllPeerAttackers(), 12));
        }
    }

    private void applyRecommendationQualityGuard(
        AnalysisReport report,
        AlertAggregator.AggregationResult aggregationResult
    ) {
        if (report == null || aggregationResult == null || report.getRecommendations() == null) {
            return;
        }
        RecommendationEvidence evidence = buildRecommendationEvidence(aggregationResult);
        List<String> recommendations = report.getRecommendations();
        int taggedCount = 0;
        int groundedCount = 0;
        for (String recommendation : recommendations) {
            if (isNotBlank(extractRecommendationTag(recommendation))) {
                taggedCount++;
            }
            if (isRecommendationGrounded(recommendation, evidence.topAttackTypes, evidence.topTargetUrls, evidence.publicIps)) {
                groundedCount++;
            }
        }

        boolean weakQuality = recommendations.size() != 5 || taggedCount < 5 || groundedCount < 3;
        if (!weakQuality) {
            return;
        }

        log.warn(
            "Recommendation quality guard triggered: size={}, tagged={}, grounded={}",
            recommendations.size(),
            taggedCount,
            groundedCount
        );

        report.setRecommendations(new ArrayList<String>());
        enrichReportWithAggregationContext(report, aggregationResult);
        if ("success".equalsIgnoreCase(report.getStatus())) {
            report.setStatus("guarded");
        }
        String guardMessage = "LLM recommendations low quality; replaced with deterministic recommendations";
        if (!isNotBlank(report.getErrorMessage())) {
            report.setErrorMessage(guardMessage);
        } else if (!report.getErrorMessage().contains(guardMessage)) {
            report.setErrorMessage(report.getErrorMessage() + "; " + guardMessage);
        }
    }

    private RecommendationEvidence buildRecommendationEvidence(AlertAggregator.AggregationResult aggregationResult) {
        RecommendationEvidence evidence = new RecommendationEvidence();
        if (aggregationResult == null || aggregationResult.getAggregatedAlerts() == null) {
            return evidence;
        }
        Map<String, Integer> attackTypeCounter = new HashMap<String, Integer>();
        LinkedHashSet<String> targetUrlSet = new LinkedHashSet<String>();
        LinkedHashSet<String> publicIpSet = new LinkedHashSet<String>();
        for (AggregatedAlert alert : aggregationResult.getAggregatedAlerts()) {
            if (alert == null) {
                continue;
            }
            if (isPublicRoutableIp(alert.getIp())) {
                publicIpSet.add(alert.getIp());
            }
            if (alert.getAttackTypes() != null) {
                for (Map.Entry<String, Integer> entry : alert.getAttackTypes().entrySet()) {
                    String key = entry.getKey();
                    Integer val = entry.getValue();
                    if (isNotBlank(key) && val != null && val > 0) {
                        attackTypeCounter.put(key, attackTypeCounter.getOrDefault(key, 0) + val);
                    }
                }
            }
            if (alert.getTargetUrls() != null) {
                for (String url : alert.getTargetUrls()) {
                    if (isNotBlank(url)) {
                        targetUrlSet.add(url.trim());
                    }
                }
            }
        }

        evidence.topAttackTypes = pickTopAttackTypes(attackTypeCounter, 5);
        evidence.topTargetUrls = new ArrayList<String>();
        for (String url : targetUrlSet) {
            evidence.topTargetUrls.add(url);
            if (evidence.topTargetUrls.size() >= 5) {
                break;
            }
        }
        evidence.publicIps = new ArrayList<String>(publicIpSet);
        return evidence;
    }

    private String buildQuantifiedSummary(
        AnalysisReport report,
        AlertAggregator.AggregationResult aggregationResult,
        int highRisk,
        int mediumRisk,
        int lowRisk,
        int maxRisk
    ) {
        int confidence = (int) Math.round(Math.max(0.0, Math.min(1.0, report.getConfidence())) * 100.0);
        String start = isNotBlank(aggregationResult.getStartTime()) ? aggregationResult.getStartTime() : "\u672a\u77e5";
        String end = isNotBlank(aggregationResult.getEndTime()) ? aggregationResult.getEndTime() : "\u672a\u77e5";
        String verdict = report.isAttackDetected() ? "\u5b58\u5728\u653b\u51fb\u6d3b\u52a8" : "\u6682\u672a\u786e\u8ba4\u653b\u51fb\u6d3b\u52a8";
        return "\u5728" + start + " \u81f3 " + end + " \u65f6\u95f4\u7a97\u5185\uff0c\u5904\u7406\u544a\u8b66" +
            aggregationResult.getProcessedAlerts() + "/" + aggregationResult.getOriginalAlerts() + "\u6761\uff0c\u6d89\u53caIP " +
            aggregationResult.getTotalIps() + "\u4e2a\uff08\u9ad8\u5371" + highRisk + "\u3001\u4e2d\u5371" + mediumRisk +
            "\u3001\u4f4e\u5371" + lowRisk + "\uff09\uff0c\u6700\u9ad8\u98ce\u9669\u5206" + maxRisk +
            "\u3002\u5f53\u524d\u5224\u5b9a\uff1a" + verdict + "\uff0c\u7f6e\u4fe1\u5ea6\u7ea6" + confidence + "%\u3002";
    }

    private String buildContextNarrative(
        AnalysisReport report,
        Set<String> phases,
        List<String> topAttackTypes,
        List<String> topTargetUrls
    ) {
        StringBuilder out = new StringBuilder();
        out.append("\u57fa\u4e8e\u805a\u5408\u544a\u8b66\u6570\u636e\uff0c\u5df2\u5b8c\u6210\u653b\u51fb\u94fe\u7814\u5224\u3002");
        out.append("\u5224\u5b9a\u7ed3\u679c\uff1a").append(report.isAttackDetected() ? "\u5b58\u5728\u653b\u51fb\u6d3b\u52a8\u3002" : "\u6682\u672a\u786e\u8ba4\u653b\u51fb\u6d3b\u52a8\u3002");

        List<String> phaseTexts = new ArrayList<String>();
        if (phases != null) {
            for (String phase : phases) {
                if (!isNotBlank(phase)) {
                    continue;
                }
                phaseTexts.add(normalizePhaseToChinese(phase));
            }
        }
        if (!phaseTexts.isEmpty()) {
            out.append("\u653b\u51fb\u9636\u6bb5\uff1a").append(joinAsChineseList(phaseTexts, 5)).append("\u3002");
        }
        if (!topAttackTypes.isEmpty()) {
            out.append("\u4e3b\u8981\u653b\u51fb\u7c7b\u578b\uff1a").append(joinAsChineseList(topAttackTypes, 5)).append("\u3002");
        }
        if (!topTargetUrls.isEmpty()) {
            out.append("\u91cd\u70b9\u53d7\u5f71\u54cdURL\uff1a").append(joinAsChineseList(topTargetUrls, 4)).append("\u3002");
        }
        out.append("\u6d3b\u52a8\u590d\u6742\u5ea6\uff1a").append(report.getAttackerSkillLevel()).append("\uff1b");
        out.append("\u81ea\u52a8\u5316\u7a0b\u5ea6\uff1a").append(report.getAutomationType()).append("\uff1b");
        out.append("\u4e3b\u8981\u610f\u56fe\uff1a").append(report.getAttackerIntent()).append("\u3002");
        return out.toString();
    }

    private List<String> buildContextAwareRecommendations(
        AnalysisReport report,
        List<String> topAttackTypes,
        List<String> topTargetUrls,
        List<String> publicIps,
        int maxRisk
    ) {
        LinkedHashMap<String, String> actionMap = new LinkedHashMap<String, String>();

        if (publicIps != null && !publicIps.isEmpty()) {
            actionMap.put("[BLOCK]", "[BLOCK] \u5728\u8fb9\u754c\u8bbe\u5907/WAF\u5c01\u7981\u9ad8\u98ce\u9669\u6e90IP " + publicIps.get(0) + "\uff0c\u5e76\u8bbe\u7f6e24\u5c0f\u65f6\u89c2\u5bdf\u671f");
        } else {
            actionMap.put("[BLOCK]", "[BLOCK] \u5bf9\u5185\u7f51\u6216\u4fdd\u7559\u5730\u5740\u6765\u6e90\u6d41\u91cf\u6267\u884c\u6e90\u4e3b\u673a\u9694\u79bb\u4e0e\u6700\u5c0f\u6743\u9650\u7b56\u7565");
        }

        actionMap.put("[PATCH]", buildPatchRecommendation(topAttackTypes, topTargetUrls));
        actionMap.put("[MONITOR]", buildMonitorRecommendation(topAttackTypes, topTargetUrls));
        actionMap.put("[REVIEW]", buildReviewRecommendation(topAttackTypes, topTargetUrls));
        if (report.isAttackDetected() || maxRisk >= HIGH_RISK_THRESHOLD) {
            actionMap.put("[IR]", "[IR] \u542f\u52a8\u5e94\u6025\u54cd\u5e94\u6d41\u7a0b\uff0c\u56fa\u5316\u53d6\u8bc1\u8bc1\u636e\u5e76\u8ddf\u8fdb\u8d26\u53f7/\u8d44\u4ea7\u7ea7\u522b\u6392\u67e5");
        } else {
            actionMap.put("[IR]", "[IR] \u5efa\u7acb\u4e8b\u4ef6\u590d\u76d8\u548c\u54cd\u5e94\u9884\u6848\uff0c\u786e\u4fdd\u9ad8\u98ce\u9669\u6307\u6807\u51fa\u73b0\u65f6\u53ef\u5feb\u901f\u5347\u7ea7");
        }

        if (report.getRecommendations() != null) {
            for (String existing : report.getRecommendations()) {
                if (!isNotBlank(existing)) {
                    continue;
                }
                String clean = existing.trim().replaceAll("\\s+", " ");
                String tag = extractRecommendationTag(clean);
                if (!isNotBlank(tag) || !actionMap.containsKey(tag)) {
                    continue;
                }
                if (!isRecommendationGrounded(clean, topAttackTypes, topTargetUrls, publicIps)) {
                    continue;
                }
                if (!clean.startsWith(tag)) {
                    clean = tag + " " + clean;
                }
                actionMap.put(tag, clean);
            }
        }
        return new ArrayList<String>(actionMap.values());
    }

    private String extractRecommendationTag(String recommendation) {
        if (!isNotBlank(recommendation)) {
            return null;
        }
        String upper = recommendation.trim().toUpperCase();
        if (upper.startsWith("[BLOCK]")) {
            return "[BLOCK]";
        }
        if (upper.startsWith("[PATCH]")) {
            return "[PATCH]";
        }
        if (upper.startsWith("[MONITOR]")) {
            return "[MONITOR]";
        }
        if (upper.startsWith("[REVIEW]")) {
            return "[REVIEW]";
        }
        if (upper.startsWith("[IR]")) {
            return "[IR]";
        }
        return null;
    }

    private boolean isRecommendationGrounded(
        String recommendation,
        List<String> topAttackTypes,
        List<String> topTargetUrls,
        List<String> publicIps
    ) {
        if (!isNotBlank(recommendation)) {
            return false;
        }
        String text = recommendation.trim().toLowerCase();
        boolean hasEvidence = false;

        if (topAttackTypes != null) {
            for (String attackType : topAttackTypes) {
                if (isNotBlank(attackType) && text.contains(attackType.toLowerCase())) {
                    hasEvidence = true;
                    break;
                }
            }
        }
        if (!hasEvidence && topTargetUrls != null) {
            for (String targetUrl : topTargetUrls) {
                if (isNotBlank(targetUrl) && text.contains(targetUrl.toLowerCase())) {
                    hasEvidence = true;
                    break;
                }
            }
        }
        if (!hasEvidence && publicIps != null) {
            for (String ip : publicIps) {
                if (isNotBlank(ip) && text.contains(ip)) {
                    hasEvidence = true;
                    break;
                }
            }
        }
        if (!hasEvidence) {
            return false;
        }

        String[] genericPhrases = new String[]{
            "关闭不必要的端口",
            "更新所有软件",
            "更新系统漏洞",
            "监控敏感数据访问",
            "审查用户权限",
            "立即响应",
            "监控所有异常",
            "monitor all",
            "update all",
            "close unnecessary ports"
        };
        for (String phrase : genericPhrases) {
            if (text.contains(phrase.toLowerCase())) {
                return false;
            }
        }
        return recommendation.trim().length() >= 12;
    }

    private String buildPatchRecommendation(List<String> topAttackTypes, List<String> topTargetUrls) {
        String sampleUrl = topTargetUrls.isEmpty() ? "\u5173\u952e\u63a5\u53e3" : topTargetUrls.get(0);
        if (containsKeyword(topAttackTypes, "deserialization")) {
            return "[PATCH] \u4f18\u5148\u4fee\u590d" + sampleUrl + "\u9644\u8fd1\u7684\u53cd\u5e8f\u5217\u5316\u5165\u53e3\uff0c\u7981\u7528\u9ad8\u5371\u7c7b\u578b\u53cd\u5c04\u4e0e\u4efb\u610f\u5bf9\u8c61\u53cd\u5e8f\u5217\u5316";
        }
        if (containsKeyword(topAttackTypes, "template-injection")) {
            return "[PATCH] \u5728" + sampleUrl + "\u7b49\u6a21\u677f\u6e32\u67d3\u70b9\u542f\u7528\u5b89\u5168\u4e0a\u4e0b\u6587\u4e0e\u53d8\u91cf\u767d\u540d\u5355\uff0c\u4fee\u590d\u6a21\u677f\u6ce8\u5165\u98ce\u9669";
        }
        if (containsKeyword(topAttackTypes, "xss")) {
            return "[PATCH] \u5bf9" + sampleUrl + "\u5b9e\u65bd\u8f93\u51fa\u7f16\u7801\u4e0eCSP\u7b56\u7565\uff0c\u5173\u95ed\u975e\u5fc5\u8981\u7684\u5185\u8054\u811a\u672c\u6267\u884c";
        }
        if (containsKeyword(topAttackTypes, "path-traversal") || containsKeyword(topAttackTypes, "directory-traversal")) {
            return "[PATCH] \u5728" + sampleUrl + "\u63a5\u53e3\u5f3a\u5316\u8def\u5f84\u89c4\u8303\u5316\u4e0e\u8bbf\u95ee\u6839\u76ee\u5f55\u9650\u5236\uff0c\u4fee\u590d\u8def\u5f84/\u76ee\u5f55\u904d\u5386\u7f3a\u9677";
        }
        return "[PATCH] \u5bf9\u9ad8\u9891\u88ab\u653b\u51fb\u63a5\u53e3\u5b9e\u65bd\u8f93\u5165\u6821\u9a8c\u3001\u9274\u6743\u52a0\u56fa\u4e0e\u5b89\u5168\u8865\u4e01\u66f4\u65b0";
    }

    private String buildMonitorRecommendation(List<String> topAttackTypes, List<String> topTargetUrls) {
        String urlPart = topTargetUrls.isEmpty() ? "\u5173\u952e\u63a5\u53e3" : joinAsChineseList(topTargetUrls, 3);
        String typePart = topAttackTypes.isEmpty() ? "\u5f02\u5e38\u8bf7\u6c42" : joinAsChineseList(topAttackTypes, 3);
        return "[MONITOR] \u9488\u5bf9" + urlPart + "\u63d0\u5347\u76d1\u63a7\u7b49\u7ea7\uff0c\u8054\u52a8\u8ddf\u8e2a" + typePart + "\u53ca4xx/5xx\u5cf0\u503c\u5f02\u5e38";
    }

    private String buildReviewRecommendation(List<String> topAttackTypes, List<String> topTargetUrls) {
        String urlPart = topTargetUrls.isEmpty() ? "\u9ad8\u98ce\u9669\u63a5\u53e3" : joinAsChineseList(topTargetUrls, 2);
        String typePart = topAttackTypes.isEmpty() ? "\u653b\u51fb\u8f7d\u8377" : joinAsChineseList(topAttackTypes, 2);
        return "[REVIEW] \u590d\u6838" + urlPart + "\u7684\u6743\u9650\u6a21\u578b\u3001\u8f93\u5165\u8fc7\u6ee4\u4e0e\u53d1\u5e03\u53d8\u66f4\uff0c\u91cd\u70b9\u56de\u6eaf" + typePart + "\u89e6\u53d1\u94fe\u8def";
    }

    private List<String> pickTopAttackTypes(Map<String, Integer> counter, int limit) {
        List<Map.Entry<String, Integer>> entries = new ArrayList<Map.Entry<String, Integer>>(counter.entrySet());
        Collections.sort(entries, new Comparator<Map.Entry<String, Integer>>() {
            @Override
            public int compare(Map.Entry<String, Integer> a, Map.Entry<String, Integer> b) {
                return Integer.compare(b.getValue(), a.getValue());
            }
        });
        List<String> out = new ArrayList<String>();
        for (Map.Entry<String, Integer> entry : entries) {
            if (out.size() >= limit) {
                break;
            }
            out.add(entry.getKey());
        }
        return out;
    }

    private List<AnalysisReport.AttackType> buildAttackTypeViews(Map<String, Integer> counter, int maxRisk) {
        List<AnalysisReport.AttackType> out = new ArrayList<AnalysisReport.AttackType>();
        if (counter == null || counter.isEmpty()) {
            return out;
        }
        List<Map.Entry<String, Integer>> entries = new ArrayList<Map.Entry<String, Integer>>(counter.entrySet());
        Collections.sort(entries, new Comparator<Map.Entry<String, Integer>>() {
            @Override
            public int compare(Map.Entry<String, Integer> a, Map.Entry<String, Integer> b) {
                return Integer.compare(b.getValue(), a.getValue());
            }
        });
        String severity = maxRisk >= HIGH_RISK_THRESHOLD ? "high" : (maxRisk >= MEDIUM_RISK_THRESHOLD ? "medium" : "low");
        int limit = Math.min(6, entries.size());
        for (int i = 0; i < limit; i++) {
            Map.Entry<String, Integer> entry = entries.get(i);
            out.add(new AnalysisReport.AttackType(
                entry.getKey(),
                "observed " + entry.getValue() + " events",
                entry.getValue(),
                severity
            ));
        }
        return out;
    }

    private String pickPrimaryAttackType(Map<String, Integer> attackTypes) {
        if (attackTypes == null || attackTypes.isEmpty()) {
            return null;
        }
        String best = null;
        int bestCount = -1;
        for (Map.Entry<String, Integer> entry : attackTypes.entrySet()) {
            if (!isNotBlank(entry.getKey())) {
                continue;
            }
            int count = entry.getValue() == null ? 0 : entry.getValue();
            if (count > bestCount) {
                best = entry.getKey();
                bestCount = count;
            }
        }
        return best;
    }

    private String sanitizePayloadSample(String payload) {
        if (!isNotBlank(payload)) {
            return null;
        }
        String compact = payload.trim().replaceAll("\\s+", " ");
        if (compact.length() <= 48) {
            return compact;
        }
        int head = 22;
        int tail = 18;
        return compact.substring(0, head) + "...[masked]..." + compact.substring(compact.length() - tail);
    }

    private boolean isStandardHttpStatusCode(int code) {
        return code >= 100 && code <= 599;
    }

    private List<AnalysisReport.PeerAttacker> convertPeerAttackers(
        List<AggregatedAlert.PeerAttacker> source,
        int limit
    ) {
        List<AnalysisReport.PeerAttacker> out = new ArrayList<AnalysisReport.PeerAttacker>();
        if (source == null || source.isEmpty() || limit <= 0) {
            return out;
        }
        LinkedHashSet<String> dedupe = new LinkedHashSet<String>();
        for (AggregatedAlert.PeerAttacker peer : source) {
            if (peer == null || !isNotBlank(peer.getIp())) {
                continue;
            }
            String relationship = isNotBlank(peer.getRelationship()) ? peer.getRelationship() : "unknown";
            String relatedTo = isNotBlank(peer.getRelatedToIp()) ? peer.getRelatedToIp() : null;
            String key = peer.getIp().trim() + "|" + relationship + "|" + (relatedTo == null ? "" : relatedTo);
            if (!dedupe.add(key)) {
                continue;
            }
            double confidence = Math.max(0.0, Math.min(1.0, peer.getConfidence()));
            out.add(new AnalysisReport.PeerAttacker(peer.getIp().trim(), relationship, confidence, relatedTo));
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private List<String> selectKeyIndicators(
        List<String> existingIndicators,
        List<String> publicIps,
        List<String> topAttackTypes,
        List<String> topTargetUrls
    ) {
        LinkedHashSet<String> out = new LinkedHashSet<String>();
        if (existingIndicators != null) {
            for (String item : existingIndicators) {
                if (!isNotBlank(item)) {
                    continue;
                }
                if (isPublicRoutableIp(item.trim())) {
                    out.add(item.trim());
                }
                if (out.size() >= 10) {
                    return new ArrayList<String>(out);
                }
            }
        }
        if (publicIps != null) {
            for (String ip : publicIps) {
                if (isNotBlank(ip)) {
                    out.add(ip.trim());
                }
                if (out.size() >= 10) {
                    return new ArrayList<String>(out);
                }
            }
        }
        for (String type : topAttackTypes) {
            if (isNotBlank(type)) {
                out.add(type);
            }
            if (out.size() >= 10) {
                return new ArrayList<String>(out);
            }
        }
        for (String url : topTargetUrls) {
            if (isNotBlank(url)) {
                out.add(url);
            }
            if (out.size() >= 10) {
                break;
            }
        }
        return new ArrayList<String>(out);
    }

    private int findMaxRiskScore(List<AggregatedAlert> alerts) {
        int maxRisk = 0;
        if (alerts == null) {
            return maxRisk;
        }
        for (AggregatedAlert alert : alerts) {
            if (alert != null) {
                maxRisk = Math.max(maxRisk, alert.getRiskScore());
            }
        }
        return maxRisk;
    }

    private String calibrateSkillLevel(Set<String> phases, List<String> topAttackTypes, int maxRisk) {
        int score = 0;
        if (containsPhase(phases, "exploitation")) {
            score += 2;
        }
        if (containsPhase(phases, "installation")) {
            score += 1;
        }
        if (containsPhase(phases, "command_control") || containsPhase(phases, "actions")) {
            score += 1;
        }
        if (containsKeyword(topAttackTypes, "code-execution")
            || containsKeyword(topAttackTypes, "deserialization")
            || containsKeyword(topAttackTypes, "template-injection")
            || containsKeyword(topAttackTypes, "command-injection")) {
            score += 2;
        }
        if (topAttackTypes != null && topAttackTypes.size() >= 5) {
            score += 1;
        }
        if (maxRisk >= HIGH_RISK_THRESHOLD) {
            score += 1;
        }
        if (score >= 6) {
            return "\u9ad8\u7ea7";
        }
        if (score >= 3) {
            return "\u4e2d\u7ea7";
        }
        return "\u521d\u7ea7";
    }

    private boolean containsPhase(Set<String> phases, String phaseToken) {
        if (phases == null || phaseToken == null) {
            return false;
        }
        for (String phase : phases) {
            if (phase != null && phase.toLowerCase().contains(phaseToken.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean containsKeyword(List<String> values, String keyword) {
        if (values == null || keyword == null) {
            return false;
        }
        String needle = keyword.toLowerCase();
        for (String value : values) {
            if (value != null && value.toLowerCase().contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private String normalizePhaseToChinese(String phase) {
        if (!isNotBlank(phase)) {
            return "\u672a\u77e5\u9636\u6bb5";
        }
        String lower = phase.trim().toLowerCase();
        if (lower.contains("recon")) {
            return "\u4fa6\u5bdf";
        }
        if (lower.contains("delivery")) {
            return "\u6295\u9012";
        }
        if (lower.contains("exploit")) {
            return "\u5229\u7528";
        }
        if (lower.contains("install")) {
            return "\u843d\u5730";
        }
        if (lower.contains("command") || lower.contains("control")) {
            return "\u63a7\u5236";
        }
        if (lower.contains("action")) {
            return "\u76ee\u6807\u884c\u4e3a";
        }
        return phase;
    }

    private String joinAsChineseList(List<String> values, int limit) {
        if (values == null || values.isEmpty() || limit <= 0) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        int count = 0;
        for (String value : values) {
            if (!isNotBlank(value)) {
                continue;
            }
            if (count > 0) {
                out.append("\u3001");
            }
            out.append(value.trim());
            count++;
            if (count >= limit) {
                break;
            }
        }
        return out.toString();
    }

    private boolean isPublicRoutableIp(String ip) {
        if (!isNotBlank(ip)) {
            return false;
        }
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            try {
                octets[i] = Integer.parseInt(parts[i]);
            } catch (Exception e) {
                return false;
            }
            if (octets[i] < 0 || octets[i] > 255) {
                return false;
            }
        }
        int a = octets[0];
        int b = octets[1];
        int c = octets[2];

        if (a == 10 || a == 127 || a == 0) {
            return false;
        }
        if (a == 100 && b >= 64 && b <= 127) {
            return false;
        }
        if (a == 169 && b == 254) {
            return false;
        }
        if (a == 172 && b >= 16 && b <= 31) {
            return false;
        }
        if (a == 192 && b == 168) {
            return false;
        }
        if (a == 192 && b == 0 && (c == 0 || c == 2)) {
            return false;
        }
        if (a == 198 && (b == 18 || b == 19)) {
            return false;
        }
        if (a == 198 && b == 51 && c == 100) {
            return false;
        }
        if (a == 203 && b == 0 && c == 113) {
            return false;
        }
        if (a >= 224) {
            return false;
        }
        return true;
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
        Map<Integer, Integer> statusCodeDistribution = new HashMap<Integer, Integer>();
        int successEvents = 0;
        int statusEvents = 0;
        LinkedHashSet<String> payloadSamples = new LinkedHashSet<String>();
        List<AnalysisReport.SourceDetail> topSources = new ArrayList<AnalysisReport.SourceDetail>();
        Map<String, Integer> attackTypeCounter = new HashMap<String, Integer>();
        LinkedHashSet<String> targetUrlSet = new LinkedHashSet<String>();

        for (AggregatedAlert alert : alerts) {
            int risk = alert.getRiskScore();
            if (risk >= HIGH_RISK_THRESHOLD) {
                high++;
            } else if (risk >= MEDIUM_RISK_THRESHOLD) {
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
                if (isNotBlank(attackType)) {
                    attackTypeCounter.put(attackType, attackTypeCounter.getOrDefault(attackType, 0) + 1);
                }
            }
            if (alert.getTargetUrls() != null) {
                for (String url : alert.getTargetUrls()) {
                    if (isNotBlank(url)) {
                        targetUrlSet.add(url.trim());
                    }
                    if (targetUrlSet.size() >= 8) {
                        break;
                    }
                }
            }
            if (alert.getStatusCodes() != null) {
                for (Map.Entry<Integer, Integer> entry : alert.getStatusCodes().entrySet()) {
                    Integer code = entry.getKey();
                    int count = entry.getValue() == null ? 0 : entry.getValue();
                    if (code == null || count <= 0 || !isStandardHttpStatusCode(code)) {
                        continue;
                    }
                    statusCodeDistribution.put(code, statusCodeDistribution.getOrDefault(code, 0) + count);
                    statusEvents += count;
                    if (code >= 200 && code < 300) {
                        successEvents += count;
                    }
                }
            }
            if (alert.getTopPayloads() != null) {
                for (String payload : alert.getTopPayloads()) {
                    if (payloadSamples.size() >= 6) {
                        break;
                    }
                    String sanitized = sanitizePayloadSample(payload);
                    if (isNotBlank(sanitized)) {
                        payloadSamples.add(sanitized);
                    }
                }
            }
            AnalysisReport.SourceDetail source = new AnalysisReport.SourceDetail();
            source.setIp(alert.getIp());
            source.setRiskScore(alert.getRiskScore());
            source.setPrimaryAttackType(pickPrimaryAttackType(alert.getAttackTypes()));
            source.setSessionCount(alert.getSessionCount());
            source.setTotalEvents(alert.getTotalEvents());
            source.setAsn(alert.getAsn());
            source.setCountry(alert.getCountry());
            source.setIsp(alert.getIsp());
            source.setThreatLevel(alert.getThreatLevel());
            source.setProfileAttackCount(alert.getProfileAttackCount());
            source.setFirstSeenTs(alert.getFirstSeenTs());
            source.setLastSeenTs(alert.getLastSeenTs());
            topSources.add(source);
        }

        report.setRiskScore(maxRisk);
        report.setRiskLevel(maxRisk >= HIGH_RISK_THRESHOLD ? "high" : (maxRisk >= MEDIUM_RISK_THRESHOLD ? "medium" : "low"));
        report.setAttackDetected(maxRisk >= MEDIUM_RISK_THRESHOLD);
        report.setConfidence(0.65);
        report.setClassification(maxRisk >= MEDIUM_RISK_THRESHOLD ? "potential_attack" : "likely_scanning");
        report.setAttackerSkillLevel("intermediate");
        report.setAutomationType("semi_auto");
        report.setAttackerIntent(maxRisk >= HIGH_RISK_THRESHOLD ? "exploitation" : "reconnaissance");
        report.setKeyIndicators(indicators);

        report.setSummary("\u964d\u7ea7\u672c\u5730\u5206\u6790\uff1a\u6d89\u53caIP " + aggregationResult.getTotalIps() +
            " \u4e2a\uff0c\u9ad8\u5371 " + high + " \u4e2a\uff0c\u4e2d\u5371 " + medium + " \u4e2a\uff0c\u4f4e\u5371 " + low +
            " \u4e2a\uff0c\u6700\u9ad8\u98ce\u9669IP " + maxRiskIp + "\u3002\u539f\u56e0\uff1a" + mapFallbackReason(reason));
        report.setAttackNarrative(buildFallbackNarrative(aggregationResult, reason, high, medium, low));
        report.setRecommendations(buildFallbackRecommendations(maxRiskIp, maxRisk));
        report.setMainAttackerIp(maxRiskIp);
        report.setWindowStart(aggregationResult.getStartTime());
        report.setWindowEnd(aggregationResult.getEndTime());
        report.setOriginalAlertCount(aggregationResult.getOriginalAlerts());
        report.setTotalIps(aggregationResult.getTotalIps());
        report.setHighRiskIps(high);
        report.setMediumRiskIps(medium);
        report.setLowRiskIps(low);
        if (!statusCodeDistribution.isEmpty()) {
            report.setStatusCodeDistribution(statusCodeDistribution);
        }
        if (statusEvents > 0) {
            report.setOverallSuccessRate(Math.round((successEvents * 10000.0) / statusEvents) / 100.0);
        }
        if (!payloadSamples.isEmpty()) {
            report.setPayloadSamples(new ArrayList<String>(payloadSamples));
        }
        report.setTopAttackTypes(pickTopAttackTypes(attackTypeCounter, 5));
        report.setTopTargetUrls(new ArrayList<String>(targetUrlSet));
        if (!topSources.isEmpty()) {
            Collections.sort(topSources, new Comparator<AnalysisReport.SourceDetail>() {
                @Override
                public int compare(AnalysisReport.SourceDetail a, AnalysisReport.SourceDetail b) {
                    return Integer.compare(b.getRiskScore(), a.getRiskScore());
                }
            });
            if (topSources.size() > 8) {
                topSources = new ArrayList<AnalysisReport.SourceDetail>(topSources.subList(0, 8));
            }
            report.setTopSources(topSources);
        }
        if (aggregationResult.getAllPeerAttackers() != null && !aggregationResult.getAllPeerAttackers().isEmpty()) {
            report.setPeerAttackers(convertPeerAttackers(aggregationResult.getAllPeerAttackers(), 12));
        }
        return report;
    }

    private String buildFallbackNarrative(AlertAggregator.AggregationResult aggregationResult, String reason, int high, int medium, int low) {
        return "\u672c\u62a5\u544a\u7531\u672c\u5730\u964d\u7ea7\u7b56\u7565\u751f\u6210\u3002\n" +
            "\u964d\u7ea7\u539f\u56e0\uff1a" + mapFallbackReason(reason) + "\n" +
            "\u603bIP\u6570\uff1a" + aggregationResult.getTotalIps() + "\n" +
            "\u603b\u4f1a\u8bdd\u6570\uff1a" + aggregationResult.getTotalSessions() + "\n" +
            "\u603b\u4e8b\u4ef6\u6570\uff1a" + aggregationResult.getTotalEvents() + "\n" +
            "\u98ce\u9669\u5206\u5e03\uff1a\u9ad8\u5371=" + high + "\uff0c\u4e2d\u5371=" + medium + "\uff0c\u4f4e\u5371=" + low + "\n" +
            "\u5efa\u8bae\u4f18\u5148\u5904\u7f6e\u9ad8\u98ce\u9669IP\u5e76\u590d\u6838\u5173\u952e\u4e1a\u52a1\u63a5\u53e3\u9632\u62a4\u7b56\u7565\u3002";
    }

    private List<String> buildFallbackRecommendations(String topRiskIp, int maxRisk) {
        List<String> recommendations = new ArrayList<String>();
        if (topRiskIp != null && !"unknown".equals(topRiskIp)) {
            recommendations.add("[BLOCK] \u5728\u8fb9\u754c\u9632\u62a4/WAF\u4e34\u65f6\u5c01\u7981\u9ad8\u98ce\u9669IP: " + topRiskIp);
        }
        recommendations.add("[MONITOR] \u63d0\u5347\u654f\u611f\u63a5\u53e3\u53ca4xx/5xx\u5f02\u5e38\u5cf0\u503c\u76d1\u63a7\u7b49\u7ea7");
        recommendations.add("[REVIEW] \u590d\u6838\u6700\u8fd1\u53d1\u5e03\u53d8\u66f4\u5e76\u52a0\u56fa\u8f93\u5165\u6821\u9a8c\u4e0e\u9274\u6743");
        if (maxRisk >= HIGH_RISK_THRESHOLD) {
            recommendations.add("[IR] \u5bf9\u9ad8\u98ce\u9669\u653b\u51fb\u6d3b\u52a8\u542f\u52a8\u5e94\u6025\u5206\u7ea7\u5904\u7f6e");
        }
        return recommendations;
    }

    private String extractSummary(String response) {
        String target = extractSection(
            response,
            SUMMARY_SECTION_START_MARKERS,
            SUMMARY_SECTION_END_MARKERS
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
        return out.isEmpty() ? "\u5206\u6790\u5b8c\u6210\u3002" : out;
    }

    private boolean detectAttackInResponse(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("no attack") || lower.contains("false positive") || response.contains("\u975e\u653b\u51fb")) {
            return false;
        }
        return lower.contains("attack") || lower.contains("exploit") || lower.contains("malicious")
            || response.contains("\u653b\u51fb") || response.contains("\u5229\u7528");
    }

    private double calculateConfidence(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("high confidence") || lower.contains("confirmed") || response.contains("\u9ad8\u7f6e\u4fe1")) {
            return 0.9;
        }
        if (lower.contains("likely") || response.contains("\u8f83\u5927\u6982\u7387")) {
            return 0.75;
        }
        if (lower.contains("possible") || lower.contains("uncertain") || response.contains("\u53ef\u80fd")) {
            return 0.55;
        }
        return 0.7;
    }

    private void applyConfidenceFallbackFromAggregation(AnalysisReport report, AlertAggregator.AggregationResult aggregationResult) {
        if (report == null) {
            return;
        }
        double current = report.getConfidence();
        if (Double.isNaN(current) || Double.isInfinite(current)) {
            current = 0.0;
        }
        if (current > 1.0) {
            report.setConfidence(1.0);
            return;
        }
        if (current > 0.01) {
            return;
        }

        int maxRisk = Math.max(0, Math.min(100, report.getRiskScore()));
        int highRisk = 0;
        int mediumRisk = 0;
        if (aggregationResult != null && aggregationResult.getAggregatedAlerts() != null) {
            for (AggregatedAlert alert : aggregationResult.getAggregatedAlerts()) {
                if (alert == null) {
                    continue;
                }
                int risk = alert.getRiskScore();
                if (risk > maxRisk) {
                    maxRisk = Math.max(0, Math.min(100, risk));
                }
                if (risk >= HIGH_RISK_THRESHOLD) {
                    highRisk++;
                } else if (risk >= MEDIUM_RISK_THRESHOLD) {
                    mediumRisk++;
                }
            }
        }

        double riskFactor = maxRisk / 100.0;
        double estimated;
        if (report.isAttackDetected()) {
            estimated = 0.62 + (0.28 * riskFactor);
            if (highRisk > 0) {
                estimated += 0.05;
            } else if (mediumRisk > 0) {
                estimated += 0.02;
            }
            estimated = Math.max(0.55, Math.min(0.95, estimated));
        } else {
            estimated = 0.45 + (0.20 * riskFactor);
            estimated = Math.max(0.35, Math.min(0.80, estimated));
        }
        report.setConfidence(estimated);
    }

    private List<String> extractRecommendations(String response) {
        List<String> recommendations = new ArrayList<String>();
        String defenseSection = extractSection(
            response,
            DEFENSE_SECTION_START_MARKERS,
            DEFENSE_SECTION_END_MARKERS
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
            if (dedup.size() >= 5) {
                break;
            }
        }
        recommendations.addAll(dedup);
        if (recommendations.isEmpty()) {
            recommendations.add("\u4f18\u5148\u5c01\u7981\u9ad8\u98ce\u9669IP\u5e76\u63d0\u5347\u5173\u952e\u63a5\u53e3\u76d1\u63a7\u7b49\u7ea7\u3002");
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
            return "\u672a\u77e5\u539f\u56e0";
        }
        if ("llm_invocation_timeout".equals(reason) || "analysis_timeout_before_llm_invocation".equals(reason)) {
            return "LLM\u8c03\u7528\u8d85\u65f6";
        }
        if ("rate_limited".equals(reason)) {
            return "LLM\u8c03\u7528\u89e6\u53d1\u9650\u6d41";
        }
        if ("circuit_open".equals(reason)) {
            return "LLM\u7194\u65ad\u5668\u5f00\u542f\uff0c\u6682\u65f6\u4e0d\u53ef\u7528";
        }
        if ("response_parse_empty_content".equals(reason) || "response_parse_failed".equals(reason)) {
            return "LLM\u8fd4\u56de\u5b58\u5728\uff0c\u4f46\u89e3\u6790\u5931\u8d25\u6216\u5185\u5bb9\u4e3a\u7a7a";
        }
        if ("network_exception".equals(reason)) {
            return "LLM\u7f51\u7edc\u8c03\u7528\u5931\u8d25";
        }
        if ("llm_execution_exception".equals(reason) || "llm_invocation_interrupted".equals(reason)) {
            return "LLM\u8c03\u7528\u6267\u884c\u5f02\u5e38";
        }
        if ("llm_empty_response".equals(reason) || "provider_empty_response".equals(reason)) {
            return "LLM\u8fd4\u56de\u7a7a\u5185\u5bb9";
        }
        if (reason.startsWith("http_status_")) {
            return "LLM\u4e0a\u6e38\u8fd4\u56de\u975e200\u72b6\u6001: " + reason.substring("http_status_".length());
        }
        if ("LLM output validation failed".equals(reason)) {
            return "LLM\u8f93\u51fa\u672a\u901a\u8fc7\u7ed3\u6784\u6821\u9a8c";
        }
        if ("LLM returned empty response".equals(reason)) {
            return "LLM\u8fd4\u56de\u7a7a\u5185\u5bb9";
        }
        if ("Analysis timeout before LLM invocation".equals(reason)) {
            return "\u5206\u6790\u5728\u8c03\u7528LLM\u524d\u8d85\u65f6";
        }
        if ("Analysis timeout after input budgeting".equals(reason)) {
            return "\u5206\u6790\u5728\u8f93\u5165\u9884\u7b97\u5904\u7406\u540e\u8d85\u65f6";
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
        if (lower.contains("advanced") || response.contains("\u9ad8\u7ea7")) {
            return "advanced";
        }
        if (lower.contains("novice") || lower.contains("script kiddie") || response.contains("\u521d\u7ea7")) {
            return "novice";
        }
        return "intermediate";
    }

    private String extractAutomation(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("fully automated") || response.contains("\u5168\u81ea\u52a8")) {
            return "fully_auto";
        }
        if (lower.contains("manual") || response.contains("\u624b\u52a8")) {
            return "manual";
        }
        return "semi_auto";
    }

    private String extractIntent(String response) {
        String lower = response.toLowerCase();
        if (lower.contains("exfiltration") || response.contains("\u7a83\u53d6")) {
            return "exfiltration";
        }
        if (lower.contains("recon") || response.contains("\u4fa6\u5bdf")) {
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
        report.setSummary("\u5206\u6790\u5931\u8d25\uff1a" + errorMessage);
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
            if (maxRisk >= HIGH_RISK_THRESHOLD) {
                report.setRiskLevel("high");
            } else if (maxRisk >= MEDIUM_RISK_THRESHOLD) {
                report.setRiskLevel("medium");
            } else {
                report.setRiskLevel("low");
            }
        }
    }

    private void sendEnabledNotifications(AnalysisReport report) {
        if (report == null) {
            return;
        }
        if (feishuNotifier != null && feishuNotifier.isEnabled()) {
            try {
                feishuNotifier.notifyAnalysisComplete(report);
            } catch (Exception e) {
                log.error("Failed to send Feishu notification: {}", e.getMessage(), e);
            }
        }
        if (weComNotifier != null && weComNotifier.isEnabled()) {
            try {
                weComNotifier.notifyAnalysisComplete(report);
            } catch (Exception e) {
                log.error("Failed to send WeCom notification: {}", e.getMessage(), e);
            }
        }
        if (dingTalkNotifier != null && dingTalkNotifier.isEnabled()) {
            try {
                dingTalkNotifier.notifyAnalysisComplete(report);
            } catch (Exception e) {
                log.error("Failed to send DingTalk notification: {}", e.getMessage(), e);
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

    private static class LlmInvocationResult {
        private final String response;
        private final String failureReason;

        private LlmInvocationResult(String response, String failureReason) {
            this.response = response;
            this.failureReason = failureReason;
        }

        public static LlmInvocationResult success(String response) {
            return new LlmInvocationResult(response, null);
        }

        public static LlmInvocationResult failure(String reason) {
            return new LlmInvocationResult(null, reason);
        }

        public String getResponse() {
            return response;
        }

        public String getFailureReason() {
            return failureReason;
        }
    }

    private static class RecommendationEvidence {
        private List<String> topAttackTypes = Collections.emptyList();
        private List<String> topTargetUrls = Collections.emptyList();
        private List<String> publicIps = Collections.emptyList();
    }

    public static class IncrementalAnalysisResult {
        private final AnalysisReport report;
        private final long newLastProcessedLine;
        private final int newAlertCount;
        private final boolean hasNewAlerts;

        private IncrementalAnalysisResult(AnalysisReport report, long newLastProcessedLine, int newAlertCount, boolean hasNewAlerts) {
            this.report = report;
            this.newLastProcessedLine = newLastProcessedLine;
            this.newAlertCount = newAlertCount;
            this.hasNewAlerts = hasNewAlerts;
        }

        public static IncrementalAnalysisResult withReport(AnalysisReport report, long newLastProcessedLine, int newAlertCount) {
            return new IncrementalAnalysisResult(report, newLastProcessedLine, newAlertCount, true);
        }

        public static IncrementalAnalysisResult noNewAlerts(long currentLastProcessedLine) {
            return new IncrementalAnalysisResult(null, currentLastProcessedLine, 0, false);
        }

        public static IncrementalAnalysisResult error(AnalysisReport report) {
            return new IncrementalAnalysisResult(report, 0L, 0, true);
        }

        public AnalysisReport getReport() {
            return report;
        }

        public long getNewLastProcessedLine() {
            return newLastProcessedLine;
        }

        public int getNewAlertCount() {
            return newAlertCount;
        }

        public boolean hasNewAlerts() {
            return hasNewAlerts;
        }
    }

    private static class IncrementalAlertReadResult {
        private final List<String> alertLogs;
        private final long startLineExclusive;
        private final long endLineInclusive;
        private final boolean hasNewAlerts;

        private IncrementalAlertReadResult(List<String> alertLogs, long startLineExclusive, long endLineInclusive, boolean hasNewAlerts) {
            this.alertLogs = alertLogs;
            this.startLineExclusive = startLineExclusive;
            this.endLineInclusive = endLineInclusive;
            this.hasNewAlerts = hasNewAlerts;
        }

        public List<String> getAlertLogs() {
            return alertLogs;
        }

        public long getStartLineExclusive() {
            return startLineExclusive;
        }

        public long getEndLineInclusive() {
            return endLineInclusive;
        }

        public boolean hasNewAlerts() {
            return hasNewAlerts;
        }
    }
}

