package org.example.input_security_starter.llm.provider.glm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.llm.provider.LlmProviderConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

public class GlmProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(GlmProvider.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final GlmConfig config;

    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private volatile long circuitOpenUntilMs = 0L;
    private final Deque<Long> requestTimestamps = new ArrayDeque<Long>();
    private final Object rateLimitLock = new Object();

    public GlmProvider(GlmConfig config) {
        this.config = config;
        log.info(
            "GlmProvider initialized: model={}, url={}, timeout(connect/read)={}/{}, retries={}, circuit(threshold/window)={}/{}, rpm={}",
            config.getModel(),
            config.getApiUrl(),
            config.getConnectTimeoutMs(),
            config.getReadTimeoutMs(),
            config.getMaxRetries(),
            config.getCircuitFailureThreshold(),
            config.getCircuitOpenWindowMs(),
            config.getMaxRequestsPerMinute()
        );
    }

    @Override
    public String getName() {
        return "glm";
    }

    @Override
    public String analyze(String prompt) {
        return sendRequest(prompt);
    }

    @Override
    public String analyzeAggregatedAlerts(String aggregatedJson) {
        if (aggregatedJson == null || aggregatedJson.trim().isEmpty()) {
            log.warn("No aggregated data to analyze");
            return null;
        }
        String prompt = buildAggregatedAnalysisPrompt(aggregatedJson);
        return sendRequest(prompt);
    }

    @Override
    public String analyzeAttackChain(List<String> alertLogs, Map<String, Object> ipIntelligence) {
        if (alertLogs == null || alertLogs.isEmpty()) {
            log.warn("No alert logs to analyze");
            return null;
        }
        String prompt = buildAnalysisPrompt(alertLogs, ipIntelligence);
        return sendRequest(prompt);
    }

    @Override
    public boolean testConnection() {
        try {
            HttpResult result = executeHttpRequest(
                "{\"model\":\"" + config.getModel() + "\"," +
                    "\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]," +
                    "\"max_tokens\":32," +
                    "\"temperature\":0.0}"
            );
            return result.statusCode == HttpURLConnection.HTTP_OK;
        } catch (Exception e) {
            log.error("GLM API connection test failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public boolean isAvailable() {
        return System.currentTimeMillis() >= circuitOpenUntilMs;
    }

    @Override
    public LlmProviderConfig getConfig() {
        return config;
    }

    private String buildAggregatedAnalysisPrompt(String aggregatedJson) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("你是企业SOC高级分析师。请仅基于输入数据输出中文报告，不要输出英文。\n");
        prompt.append("必须严格使用以下Markdown结构，且每个标题只出现一次：\n");
        prompt.append("### 执行摘要\n");
        prompt.append("### 攻击活动画像\n");
        prompt.append("### 攻击链分析\n");
        prompt.append("### 防御建议\n");
        prompt.append("\n");
        prompt.append("约束：\n");
        prompt.append("1) 只引用输入中的事实，禁止臆测。\n");
        prompt.append("2) 防御建议只给5条，使用编号1-5。\n");
        prompt.append("3) 每条防御建议必须具体到动作与对象，格式建议为 [BLOCK]/[PATCH]/[MONITOR]/[REVIEW]/[TRAIN]。\n");
        prompt.append("4) 不要重复段落，不要重复建议。\n\n");
        prompt.append("聚合数据JSON：\n```json\n");
        prompt.append(aggregatedJson);
        prompt.append("\n```\n");
        return prompt.toString();
    }

    @SuppressWarnings("unchecked")
    private String buildAnalysisPrompt(List<String> alertLogs, Map<String, Object> ipIntelligence) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("You are a SOC analyst. Analyze attack-chain alerts and provide a concise investigation report.\n");
        if (ipIntelligence != null && !ipIntelligence.isEmpty()) {
            prompt.append("IP intelligence is included for correlation.\n");
        }
        prompt.append("Alert logs JSON lines:\n");
        for (String alertLog : alertLogs) {
            prompt.append(alertLog).append('\n');
        }
        return prompt.toString();
    }

    private String sendRequest(String prompt) {
        if (prompt == null || prompt.isEmpty()) {
            return null;
        }

        long now = System.currentTimeMillis();
        if (now < circuitOpenUntilMs) {
            log.warn("Circuit breaker is open until {}. Request skipped.", circuitOpenUntilMs);
            return null;
        }

        if (!tryAcquireRateLimitSlot(now)) {
            log.warn("Rate limit reached ({} requests/min). Request rejected.", config.getMaxRequestsPerMinute());
            return null;
        }

        String jsonPayload = buildJsonRequest(prompt);
        int attempts = config.getMaxRetries() + 1;

        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                HttpResult result = executeHttpRequest(jsonPayload);
                if (result.statusCode == HttpURLConnection.HTTP_OK) {
                    onRequestSuccess();
                    return parseResponse(result.body);
                }

                if (isRetriableStatus(result.statusCode) && attempt < attempts) {
                    onRequestFailure("http_status_" + result.statusCode);
                    sleepBackoff(attempt);
                    continue;
                }

                onRequestFailure("http_status_" + result.statusCode);
                log.error("GLM API returned non-success status {}. body={}", result.statusCode, abbreviate(result.body));
                return null;
            } catch (IOException ioe) {
                if (attempt < attempts) {
                    onRequestFailure("network_exception");
                    sleepBackoff(attempt);
                    continue;
                }
                onRequestFailure("network_exception");
                log.error("GLM request failed after retries: {}", ioe.getMessage());
                return null;
            } catch (Exception e) {
                onRequestFailure("unexpected_exception");
                log.error("Unexpected GLM request failure: {}", e.getMessage(), e);
                return null;
            }
        }

        return null;
    }

    protected HttpResult executeHttpRequest(String jsonPayload) throws IOException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(config.getApiUrl());
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + config.getApiKey());
            conn.setDoOutput(true);
            conn.setConnectTimeout(config.getConnectTimeoutMs());
            conn.setReadTimeout(config.getReadTimeoutMs());

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int statusCode = conn.getResponseCode();
            String body = readResponseBody(conn, statusCode);
            return new HttpResult(statusCode, body);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private String readResponseBody(HttpURLConnection conn, int statusCode) throws IOException {
        InputStream stream = statusCode >= 200 && statusCode < 300 ? conn.getInputStream() : conn.getErrorStream();
        if (stream == null) {
            return "";
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
        }
        return response.toString();
    }

    private void onRequestSuccess() {
        consecutiveFailures.set(0);
        circuitOpenUntilMs = 0L;
    }

    private void onRequestFailure(String reason) {
        int failures = consecutiveFailures.incrementAndGet();
        if (failures >= config.getCircuitFailureThreshold()) {
            long until = System.currentTimeMillis() + config.getCircuitOpenWindowMs();
            circuitOpenUntilMs = until;
            log.warn(
                "Circuit opened due to {} consecutive failures. reason={}, openUntil={}",
                failures,
                reason,
                until
            );
            consecutiveFailures.set(0);
        }
    }

    private boolean tryAcquireRateLimitSlot(long nowMs) {
        long windowStart = nowMs - 60_000L;
        synchronized (rateLimitLock) {
            while (!requestTimestamps.isEmpty() && requestTimestamps.peekFirst() < windowStart) {
                requestTimestamps.pollFirst();
            }
            if (requestTimestamps.size() >= config.getMaxRequestsPerMinute()) {
                return false;
            }
            requestTimestamps.addLast(nowMs);
            return true;
        }
    }

    private boolean isRetriableStatus(int statusCode) {
        return statusCode == 429 || statusCode >= 500;
    }

    private void sleepBackoff(int attempt) {
        long exp = config.getRetryBaseDelayMs() * (1L << Math.max(0, attempt - 1));
        long capped = Math.min(config.getRetryMaxDelayMs(), exp);
        long jitter = ThreadLocalRandom.current().nextLong(Math.max(1L, capped / 2L));
        long delay = Math.min(config.getRetryMaxDelayMs(), capped + jitter);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private String buildJsonRequest(String prompt) {
        return "{\"model\":\"" + config.getModel() + "\"," +
            "\"messages\":[{\"role\":\"user\",\"content\":\"" + escapeJson(prompt) + "\"}]," +
            "\"max_tokens\":4096," +
            "\"temperature\":0.3}";
    }

    private String parseResponse(String jsonResponse) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(jsonResponse);
            if (root.has("choices") && root.get("choices").isArray() && root.get("choices").size() > 0) {
                JsonNode message = root.get("choices").get(0).get("message");
                if (message != null && message.has("content")) {
                    return message.get("content").asText();
                }
            }
            return null;
        } catch (Exception e) {
            log.warn("Failed to parse GLM response as JSON: {}", e.getMessage());
            return extractContentFallback(jsonResponse);
        }
    }

    private String extractContentFallback(String jsonResponse) {
        if (jsonResponse == null) {
            return null;
        }
        int contentIndex = jsonResponse.indexOf("\"content\"");
        if (contentIndex < 0) {
            return null;
        }
        int firstQuote = jsonResponse.indexOf('"', contentIndex + 9);
        if (firstQuote < 0) {
            return null;
        }
        int valueStart = jsonResponse.indexOf('"', firstQuote + 1);
        if (valueStart < 0) {
            return null;
        }
        valueStart++;

        StringBuilder value = new StringBuilder();
        boolean escaping = false;
        for (int i = valueStart; i < jsonResponse.length(); i++) {
            char c = jsonResponse.charAt(i);
            if (escaping) {
                value.append(c);
                escaping = false;
                continue;
            }
            if (c == '\\') {
                escaping = true;
                continue;
            }
            if (c == '"') {
                break;
            }
            value.append(c);
        }

        return value.toString()
            .replace("\\n", "\n")
            .replace("\\r", "")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }

    private String escapeJson(String str) {
        return str.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    private String abbreviate(String content) {
        if (content == null) {
            return "null";
        }
        if (content.length() <= 300) {
            return content;
        }
        return content.substring(0, 300) + "...";
    }

    public static class HttpResult {
        private final int statusCode;
        private final String body;

        public HttpResult(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getBody() {
            return body;
        }
    }
}
