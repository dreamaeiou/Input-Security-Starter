package org.example.input_security_starter.benchmark;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class FalsePositiveBenchmarkTest {

    /**
     * Baseline regression thresholds.
     * You can tighten them in CI:
     * -Dfpr.max=0.05 -Dedge.fpr.max=0.20 -Dattack.detect.min=0.95
     */
    private static final double MAX_FPR = Double.parseDouble(System.getProperty("fpr.max", "0.15"));
    private static final double MAX_EDGE_FPR = Double.parseDouble(System.getProperty("edge.fpr.max", "0.35"));
    private static final double MIN_ATTACK_DETECTION_RATE = Double.parseDouble(System.getProperty("attack.detect.min", "0.90"));

    private OptimizedRuleEngine ruleEngine;

    @BeforeEach
    void setUp() {
        InputSecurityProperties properties = new InputSecurityProperties();
        ruleEngine = new OptimizedRuleEngine();
        ruleEngine.loadRules(properties.getRules());
    }

    @Test
    @DisplayName("Offline FPR benchmark should stay under thresholds")
    void shouldControlFalsePositiveRate() throws IOException {
        List<Sample> normalSamples = loadSamples("benchmark/normal-inputs.txt");
        List<Sample> edgeSamples = loadSamples("benchmark/edge-normal-inputs.txt");
        List<Sample> attackSamples = loadSamples("benchmark/attack-inputs.txt");

        BenchmarkResult normalResult = runEvaluation(normalSamples, false);
        BenchmarkResult edgeResult = runEvaluation(edgeSamples, false);
        BenchmarkResult attackResult = runEvaluation(attackSamples, true);

        printSummary(normalResult, edgeResult, attackResult);

        assertTrue(normalResult.rate() <= MAX_FPR,
                String.format("Normal-set FPR too high: %.2f%% > %.2f%%", normalResult.rate() * 100, MAX_FPR * 100));
        assertTrue(edgeResult.rate() <= MAX_EDGE_FPR,
                String.format("Edge-set FPR too high: %.2f%% > %.2f%%", edgeResult.rate() * 100, MAX_EDGE_FPR * 100));
        assertTrue(attackResult.rate() >= MIN_ATTACK_DETECTION_RATE,
                String.format("Attack detection rate too low: %.2f%% < %.2f%%", attackResult.rate() * 100, MIN_ATTACK_DETECTION_RATE * 100));
    }

    private BenchmarkResult runEvaluation(List<Sample> samples, boolean expectBlocked) {
        int hitCount = 0;
        Map<String, Integer> hitByRule = new LinkedHashMap<>();
        List<String> mismatches = new ArrayList<>();

        for (Sample sample : samples) {
            String matchedRule = ruleEngine.match(sample.value);
            boolean blocked = matchedRule != null;

            if (blocked) {
                hitCount++;
                hitByRule.put(matchedRule, hitByRule.getOrDefault(matchedRule, 0) + 1);
            }

            if (blocked != expectBlocked) {
                String message = String.format("source=%s, value=%s, matchedRule=%s",
                        sample.source, sample.value, matchedRule);
                mismatches.add(message);
            }
        }

        return new BenchmarkResult(samples.size(), hitCount, hitByRule, mismatches);
    }

    private void printSummary(BenchmarkResult normalResult, BenchmarkResult edgeResult, BenchmarkResult attackResult) {
        System.out.println("=== Offline False Positive Benchmark ===");
        System.out.printf("Normal set: total=%d, falsePositives=%d, FPR=%.2f%%%n",
                normalResult.total, normalResult.hitCount, normalResult.rate() * 100);
        System.out.printf("Edge set:   total=%d, falsePositives=%d, Edge-FPR=%.2f%%%n",
                edgeResult.total, edgeResult.hitCount, edgeResult.rate() * 100);
        System.out.printf("Attack set: total=%d, detected=%d, detectionRate=%.2f%%%n",
                attackResult.total, attackResult.hitCount, attackResult.rate() * 100);

        Map<String, Integer> merged = new LinkedHashMap<>();
        mergeCounts(merged, normalResult.hitByRule);
        mergeCounts(merged, edgeResult.hitByRule);
        List<Map.Entry<String, Integer>> sorted = new ArrayList<>(merged.entrySet());
        sorted.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));

        System.out.println("Top false-positive rules:");
        if (sorted.isEmpty()) {
            System.out.println("  none");
        } else {
            int limit = Math.min(5, sorted.size());
            for (int i = 0; i < limit; i++) {
                Map.Entry<String, Integer> item = sorted.get(i);
                System.out.printf("  %d) %s -> %d%n", i + 1, item.getKey(), item.getValue());
            }
        }

        if (!normalResult.mismatches.isEmpty()) {
            System.out.println("Normal-set mismatches:");
            for (String mismatch : normalResult.mismatches) {
                System.out.println("  " + mismatch);
            }
        }
        if (!edgeResult.mismatches.isEmpty()) {
            System.out.println("Edge-set mismatches:");
            for (String mismatch : edgeResult.mismatches) {
                System.out.println("  " + mismatch);
            }
        }
        if (!attackResult.mismatches.isEmpty()) {
            System.out.println("Attack-set misses:");
            for (String mismatch : attackResult.mismatches) {
                System.out.println("  " + mismatch);
            }
        }
    }

    private void mergeCounts(Map<String, Integer> merged, Map<String, Integer> counts) {
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            merged.put(entry.getKey(), merged.getOrDefault(entry.getKey(), 0) + entry.getValue());
        }
    }

    private List<Sample> loadSamples(String resourcePath) throws IOException {
        InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
        if (stream == null) {
            throw new IOException("Resource not found: " + resourcePath);
        }

        List<Sample> samples = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }

                String[] parts = trimmed.split("\\|", 2);
                if (parts.length != 2) {
                    continue;
                }

                samples.add(new Sample(parts[0].trim(), parts[1].trim()));
            }
        }
        return Collections.unmodifiableList(samples);
    }

    private static class Sample {
        private final String source;
        private final String value;

        private Sample(String source, String value) {
            this.source = source;
            this.value = value;
        }
    }

    private static class BenchmarkResult {
        private final int total;
        private final int hitCount;
        private final Map<String, Integer> hitByRule;
        private final List<String> mismatches;

        private BenchmarkResult(int total, int hitCount, Map<String, Integer> hitByRule, List<String> mismatches) {
            this.total = total;
            this.hitCount = hitCount;
            this.hitByRule = hitByRule;
            this.mismatches = mismatches;
        }

        private double rate() {
            if (total == 0) {
                return 0.0;
            }
            return (double) hitCount / total;
        }
    }
}
