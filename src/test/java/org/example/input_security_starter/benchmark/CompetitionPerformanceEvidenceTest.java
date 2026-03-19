package org.example.input_security_starter.benchmark;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.example.input_security_starter.filter.InputSecurityFilter;
import org.example.input_security_starter.tracker.AttackChainTracker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Competition-oriented benchmark suite.
 *
 * This test is designed to produce concise, reusable performance evidence for
 * project documentation and presentations rather than only pass/fail checks.
 */
class CompetitionPerformanceEvidenceTest {

    private static final int RULE_ENGINE_WARMUP = 2_000;
    private static final int RULE_ENGINE_ITERATIONS = 20_000;
    private static final int FILTER_WARMUP = 300;
    private static final int FILTER_ITERATIONS = 2_000;
    private static final int EVENT_RECORDER_ITERATIONS = 5_000;
    private static final int TRACKER_ITERATIONS = 2_000;

    private OptimizedRuleEngine ruleEngine;
    private EventRecorder eventRecorder;
    private InputSecurityFilter filter;
    private AttackChainTracker tracker;

    @BeforeEach
    void setUp() {
        InputSecurityProperties properties = new InputSecurityProperties();
        properties.setEnabled(true);
        properties.setMode(InputSecurityProperties.Mode.BLOCK);

        ruleEngine = new OptimizedRuleEngine();
        ruleEngine.loadRules(properties.getRules());

        eventRecorder = new EventRecorder("competition-benchmark.log", 10, 2, false);
        tracker = new AttackChainTracker(1000, 10, 20, 2);
        eventRecorder.setAttackChainTracker(tracker);
        filter = new InputSecurityFilter(properties, ruleEngine, eventRecorder);
    }

    @Test
    @DisplayName("Competition benchmark should produce reusable evidence")
    void shouldProduceCompetitionBenchmarkEvidence() throws Exception {
        List<Metric> metrics = new ArrayList<Metric>();

        metrics.add(benchmarkRuleEngineSafeInput());
        metrics.add(benchmarkRuleEngineAttackInput());
        metrics.add(benchmarkFilterSafeRequest());
        metrics.add(benchmarkFilterBlockedRequest());
        metrics.add(benchmarkEventRecorderWrite());
        metrics.add(benchmarkAttackChainTracking());

        String report = renderMarkdown(metrics);
        System.out.println(report);
        writeReport(report);

        for (Metric metric : metrics) {
            assertTrue(metric.throughputOpsPerSec > 0.0, metric.name + " should have positive throughput");
        }
    }

    private Metric benchmarkRuleEngineSafeInput() {
        String payload = "student portal search keyword";
        for (int i = 0; i < RULE_ENGINE_WARMUP; i++) {
            ruleEngine.match(payload);
        }

        long start = System.nanoTime();
        int detections = 0;
        for (int i = 0; i < RULE_ENGINE_ITERATIONS; i++) {
            if (ruleEngine.match(payload) != null) {
                detections++;
            }
        }
        long elapsed = System.nanoTime() - start;
        return Metric.of("RuleEngine Safe Input", RULE_ENGINE_ITERATIONS, elapsed, detections, 0);
    }

    private Metric benchmarkRuleEngineAttackInput() {
        String payload = "<script>alert(1)</script>";
        for (int i = 0; i < RULE_ENGINE_WARMUP; i++) {
            ruleEngine.match(payload);
        }

        long start = System.nanoTime();
        int detections = 0;
        for (int i = 0; i < RULE_ENGINE_ITERATIONS; i++) {
            if (ruleEngine.match(payload) != null) {
                detections++;
            }
        }
        long elapsed = System.nanoTime() - start;
        return Metric.of("RuleEngine Attack Input", RULE_ENGINE_ITERATIONS, elapsed, detections, RULE_ENGINE_ITERATIONS);
    }

    private Metric benchmarkFilterSafeRequest() throws Exception {
        for (int i = 0; i < FILTER_WARMUP; i++) {
            executeSafeFilterRequest(i);
        }

        long start = System.nanoTime();
        int blocked = 0;
        for (int i = 0; i < FILTER_ITERATIONS; i++) {
            MockHttpServletResponse response = executeSafeFilterRequest(i);
            if (response.getStatus() == 403) {
                blocked++;
            }
        }
        long elapsed = System.nanoTime() - start;
        return Metric.of("Filter Safe Request", FILTER_ITERATIONS, elapsed, FILTER_ITERATIONS - blocked, 0);
    }

    private Metric benchmarkFilterBlockedRequest() throws Exception {
        for (int i = 0; i < FILTER_WARMUP; i++) {
            executeAttackFilterRequest();
        }

        long start = System.nanoTime();
        int blocked = 0;
        for (int i = 0; i < FILTER_ITERATIONS; i++) {
            MockHttpServletResponse response = executeAttackFilterRequest();
            if (response.getStatus() == 403) {
                blocked++;
            }
        }
        long elapsed = System.nanoTime() - start;
        return Metric.of("Filter Attack Request", FILTER_ITERATIONS, elapsed, blocked, FILTER_ITERATIONS);
    }

    private Metric benchmarkEventRecorderWrite() {
        long memoryBefore = usedMemory();
        long start = System.nanoTime();
        for (int i = 0; i < EVENT_RECORDER_ITERATIONS; i++) {
            eventRecorder.record(new SecurityEvent(
                "sql-injection",
                "payload-" + i,
                "/api/orders",
                "POST",
                "127.0.0.1"
            ));
        }
        long elapsed = System.nanoTime() - start;
        long memoryAfter = usedMemory();

        Metric metric = Metric.of("EventRecorder Write", EVENT_RECORDER_ITERATIONS, elapsed, EVENT_RECORDER_ITERATIONS, EVENT_RECORDER_ITERATIONS);
        metric.memoryDeltaMb = bytesToMb(Math.max(0L, memoryAfter - memoryBefore));
        return metric;
    }

    private Metric benchmarkAttackChainTracking() {
        long start = System.nanoTime();
        int processedEvents = 0;
        for (int i = 0; i < TRACKER_ITERATIONS; i++) {
            String ip = "10.0.0." + (i % 50);
            String sessionId = "sess-" + (i % 50);
            tracker.onSecurityEvent(new SecurityEvent.Builder("ssrf-attack", "http://127.0.0.1", "/proxy", "GET")
                .ipAddress(ip)
                .sessionId(sessionId)
                .build());
            tracker.onSecurityEvent(new SecurityEvent.Builder("sql-injection", "' OR 1=1 --", "/login", "GET")
                .ipAddress(ip)
                .sessionId(sessionId)
                .build());
            tracker.onSecurityEvent(new SecurityEvent.Builder("command-injection", "; cat /etc/passwd", "/exec", "POST")
                .ipAddress(ip)
                .sessionId(sessionId)
                .build());
            processedEvents += 3;
        }
        long elapsed = System.nanoTime() - start;
        return Metric.of("AttackChain Tracking", processedEvents, elapsed, processedEvents, processedEvents);
    }

    private MockHttpServletResponse executeSafeFilterRequest(int index) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/search");
        request.setMethod("GET");
        request.addParameter("keyword", "student-" + index);

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private MockHttpServletResponse executeAttackFilterRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/search");
        request.setMethod("GET");
        request.addParameter("keyword", "<script>alert(1)</script>");

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private String renderMarkdown(List<Metric> metrics) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Competition Benchmark Summary\n\n");
        sb.append("| Scenario | Ops | Total Time (ms) | Avg Latency (us) | Throughput (ops/s) | Detection/Success | Memory Delta (MB) |\n");
        sb.append("| :-- | --: | --: | --: | --: | --: | --: |\n");
        for (Metric metric : metrics) {
            sb.append("| ")
                .append(metric.name).append(" | ")
                .append(metric.operations).append(" | ")
                .append(String.format("%.2f", metric.totalTimeMs)).append(" | ")
                .append(String.format("%.2f", metric.avgLatencyMicros)).append(" | ")
                .append(String.format("%.0f", metric.throughputOpsPerSec)).append(" | ")
                .append(metric.successCount).append("/").append(metric.expectedSuccessCount).append(" | ")
                .append(String.format("%.2f", metric.memoryDeltaMb)).append(" |\n");
        }
        sb.append("\n");
        sb.append("> Note: benchmark results depend on local CPU, JDK, and operating system. ");
        sb.append("Use the same machine and a warm JVM when collecting final competition data.\n");
        return sb.toString();
    }

    private void writeReport(String report) throws IOException {
        File targetDir = new File("target");
        if (!targetDir.exists()) {
            targetDir.mkdirs();
        }
        File reportFile = new File(targetDir, "competition-benchmark-summary.md");
        FileWriter writer = new FileWriter(reportFile, false);
        try {
            writer.write(report);
        } finally {
            writer.close();
        }
    }

    private long usedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private double bytesToMb(long bytes) {
        return bytes / 1024.0 / 1024.0;
    }

    private static class Metric {
        private final String name;
        private final int operations;
        private final double totalTimeMs;
        private final double avgLatencyMicros;
        private final double throughputOpsPerSec;
        private final int successCount;
        private final int expectedSuccessCount;
        private double memoryDeltaMb;

        private Metric(String name, int operations, double totalTimeMs, double avgLatencyMicros,
                       double throughputOpsPerSec, int successCount, int expectedSuccessCount) {
            this.name = name;
            this.operations = operations;
            this.totalTimeMs = totalTimeMs;
            this.avgLatencyMicros = avgLatencyMicros;
            this.throughputOpsPerSec = throughputOpsPerSec;
            this.successCount = successCount;
            this.expectedSuccessCount = expectedSuccessCount;
            this.memoryDeltaMb = 0.0;
        }

        private static Metric of(String name, int operations, long elapsedNanos, int successCount, int expectedSuccessCount) {
            double totalTimeMs = elapsedNanos / 1_000_000.0;
            double avgLatencyMicros = elapsedNanos / 1_000.0 / operations;
            double throughputOpsPerSec = operations / (elapsedNanos / (double) TimeUnit.SECONDS.toNanos(1));
            return new Metric(name, operations, totalTimeMs, avgLatencyMicros, throughputOpsPerSec, successCount, expectedSuccessCount);
        }
    }
}
