package org.example.input_security_starter.llm.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.llm.analysis.LlmAnalysisService;
import org.example.input_security_starter.llm.provider.glm.GlmConfig;
import org.example.input_security_starter.llm.provider.glm.GlmProvider;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LlmSteadyStateProtectionTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldRetryOnRetriableErrors() {
        SequencedGlmProvider provider = new SequencedGlmProvider(10, 10, 2, 1, 1, 3, 5000, 100);
        provider.enqueueStatus(500, "{}");
        provider.enqueueStatus(200, "{\"choices\":[{\"message\":{\"content\":\"Summary\\n- recommend block\"}}]}");

        String response = provider.analyzeAggregatedAlerts("{\"x\":1}");

        assertNotNull(response);
        assertEquals(2, provider.getCallCount());
    }

    @Test
    void shouldOpenCircuitAfterConsecutiveFailures() {
        SequencedGlmProvider provider = new SequencedGlmProvider(10, 10, 0, 1, 1, 1, 5000, 100);
        provider.enqueueIoException();

        String first = provider.analyzeAggregatedAlerts("{\"x\":1}");
        String second = provider.analyzeAggregatedAlerts("{\"x\":2}");

        assertNull(first);
        assertNull(second);
        assertEquals(1, provider.getCallCount());
    }

    @Test
    void shouldEnforceRateLimitPerMinute() {
        SequencedGlmProvider provider = new SequencedGlmProvider(10, 10, 0, 1, 1, 3, 5000, 1);
        provider.enqueueStatus(200, "{\"choices\":[{\"message\":{\"content\":\"Summary\\n- recommend monitor\"}}]}");

        String first = provider.analyzeAggregatedAlerts("{\"x\":1}");
        String second = provider.analyzeAggregatedAlerts("{\"x\":2}");

        assertNotNull(first);
        assertNull(second);
        assertEquals(1, provider.getCallCount());
    }

    @Test
    void shouldFallbackWhenLlmOutputValidationFails() throws Exception {
        File logFile = createMinimalAlertLog();
        try {
            SequencedGlmProvider provider = new SequencedGlmProvider(10, 10, 0, 1, 1, 3, 5000, 100);
            provider.enqueueStatus(200, "{\"choices\":[{\"message\":{\"content\":\"too short\"}}]}");

            LlmAnalysisService service = new LlmAnalysisService(
                provider,
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                2000,
                10,
                5,
                5000,
                null
            );

            AnalysisReport report = service.analyzeAttackChainAlerts();
            assertNotNull(report);
            assertEquals("degraded", report.getStatus());
            assertTrue(report.getSummary().contains("降级本地分析"));
        } finally {
            logFile.delete();
        }
    }

    @Test
    void shouldFallbackOnSingleAnalysisTimeoutAndKeepConcurrencyGuard() throws Exception {
        File logFile = createMinimalAlertLog();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            SequencedGlmProvider slowProvider = new SequencedGlmProvider(10, 10, 0, 1, 1, 3, 5000, 100) {
                @Override
                protected HttpResult executeHttpRequest(String jsonPayload) throws IOException {
                    calls.incrementAndGet();
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return new HttpResult(200, "{\"choices\":[{\"message\":{\"content\":\"Summary\\n- recommend block\"}}]}");
                }
            };

            final LlmAnalysisService service = new LlmAnalysisService(
                slowProvider,
                null,
                null,
                logFile.getAbsolutePath(),
                50,
                2000,
                10,
                5,
                100,
                null
            );

            CountDownLatch startLatch = new CountDownLatch(1);
            Future<AnalysisReport> f1 = pool.submit(() -> {
                startLatch.await(1, TimeUnit.SECONDS);
                return service.analyzeAttackChainAlerts();
            });
            Future<AnalysisReport> f2 = pool.submit(() -> {
                startLatch.await(1, TimeUnit.SECONDS);
                return service.analyzeAttackChainAlerts();
            });
            startLatch.countDown();

            AnalysisReport r1 = f1.get(3, TimeUnit.SECONDS);
            AnalysisReport r2 = f2.get(3, TimeUnit.SECONDS);

            assertNotNull(r1);
            assertNotNull(r2);
            assertTrue(
                "error".equals(r1.getStatus()) || "error".equals(r2.getStatus()),
                "One request should be rejected by concurrency guard"
            );
            assertTrue(
                "degraded".equals(r1.getStatus()) || "degraded".equals(r2.getStatus()),
                "One request should degrade on timeout"
            );
        } finally {
            pool.shutdownNow();
            logFile.delete();
        }
    }

    private File createMinimalAlertLog() throws Exception {
        File file = File.createTempFile("llm-steady-state", ".log");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            Map<String, Object> alert = new HashMap<String, Object>();
            alert.put("alert_type", "attack_chain_detected");
            alert.put("session_id", "sess-1");
            alert.put("client_ip", "1.2.3.4");
            alert.put("current_phase", "exploitation");
            alert.put("triggered_phases", new String[]{"reconnaissance", "delivery", "exploitation"});
            alert.put("event_count", 2);
            alert.put("duration_ms", 1000);
            alert.put("ts", System.currentTimeMillis());
            alert.put("events", new Object[]{
                event("sql-injection", "/api/order", "' OR 1=1 --"),
                event("xss-attack", "/api/search", "<script>alert(1)</script>")
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
        event.put("ip", "1.2.3.4");
        event.put("payload_preview", payload);
        event.put("method", "GET");
        return event;
    }

    private static class SequencedGlmProvider extends GlmProvider {
        private final ArrayDeque<Object> queue = new ArrayDeque<Object>();
        protected final AtomicInteger calls = new AtomicInteger(0);

        SequencedGlmProvider(
            int connectTimeoutMs,
            int readTimeoutMs,
            int retries,
            long retryBaseDelayMs,
            long retryMaxDelayMs,
            int circuitFailureThreshold,
            long circuitOpenWindowMs,
            int rpm
        ) {
            super(createConfig(connectTimeoutMs, readTimeoutMs, retries, retryBaseDelayMs, 
                               retryMaxDelayMs, circuitFailureThreshold, circuitOpenWindowMs, rpm));
        }

        private static GlmConfig createConfig(int connectTimeoutMs, int readTimeoutMs, int retries,
                                               long retryBaseDelayMs, long retryMaxDelayMs,
                                               int circuitFailureThreshold, long circuitOpenWindowMs, int rpm) {
            GlmConfig config = new GlmConfig("http://example.invalid", "test", "glm-test");
            config.setConnectTimeoutMs(connectTimeoutMs);
            config.setReadTimeoutMs(readTimeoutMs);
            config.setMaxRetries(retries);
            config.setRetryBaseDelayMs(retryBaseDelayMs);
            config.setRetryMaxDelayMs(retryMaxDelayMs);
            config.setCircuitFailureThreshold(circuitFailureThreshold);
            config.setCircuitOpenWindowMs(circuitOpenWindowMs);
            config.setMaxRequestsPerMinute(rpm);
            return config;
        }

        void enqueueStatus(int status, String body) {
            queue.add(new HttpResult(status, body));
        }

        void enqueueIoException() {
            queue.add(new IOException("network down"));
        }

        int getCallCount() {
            return calls.get();
        }

        @Override
        protected HttpResult executeHttpRequest(String jsonPayload) throws IOException {
            calls.incrementAndGet();
            Object next = queue.pollFirst();
            if (next == null) {
                return new HttpResult(200, "{\"choices\":[{\"message\":{\"content\":\"Summary\\n- recommend monitor\"}}]}");
            }
            if (next instanceof IOException) {
                throw (IOException) next;
            }
            return (HttpResult) next;
        }
    }
}
