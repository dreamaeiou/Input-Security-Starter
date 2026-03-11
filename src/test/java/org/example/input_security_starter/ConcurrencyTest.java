package org.example.input_security_starter;

import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.example.input_security_starter.filter.InputSecurityFilter;
import org.example.input_security_starter.model.SecurityRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发测试类
 * 验证组件在多线程环境下的线程安全性
 */
class ConcurrencyTest {

    private EventRecorder eventRecorder;
    private OptimizedRuleEngine ruleEngine;
    private InputSecurityFilter filter;
    private InputSecurityProperties properties;

    @BeforeEach
    void setUp() {
        eventRecorder = new EventRecorder();
        
        properties = new InputSecurityProperties();
        properties.setEnabled(true);
        properties.setMode(InputSecurityProperties.Mode.BLOCK);
        
        ruleEngine = new OptimizedRuleEngine();
        ruleEngine.loadRules(createTestRules());
        
        filter = new InputSecurityFilter(properties, ruleEngine, eventRecorder);
    }

    // ==================== EventRecorder 并发测试 ====================

    @Test
    @DisplayName("EventRecorder should be thread-safe for concurrent writes")
    void testEventRecorderConcurrentWrites() throws InterruptedException {
        int threadCount = 10;
        int eventsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < eventsPerThread; j++) {
                        SecurityEvent event = new SecurityEvent(
                            "rule-" + threadId + "-" + j,
                            "input-" + threadId + "-" + j,
                            "/api/test",
                            "GET",
                            "127.0.0.1"
                        );
                        eventRecorder.record(event);
                        successCount.incrementAndGet();
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(30, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "All threads should complete within timeout");
        assertEquals(threadCount * eventsPerThread, successCount.get(), "All events should be recorded");
        
        List<SecurityEvent> events = eventRecorder.getRecentEvents(threadCount * eventsPerThread + 10);
        assertTrue(events.size() <= 100000, "Events should not exceed max limit");
    }

    @Test
    @DisplayName("EventRecorder should handle concurrent reads and writes")
    void testEventRecorderConcurrentReadWrite() throws InterruptedException {
        int writerThreads = 5;
        int readerThreads = 5;
        int operationsPerThread = 50;
        
        ExecutorService executor = Executors.newFixedThreadPool(writerThreads + readerThreads);
        CountDownLatch latch = new CountDownLatch(writerThreads + readerThreads);
        AtomicInteger writeCount = new AtomicInteger(0);
        AtomicInteger readCount = new AtomicInteger(0);

        // Writer threads
        for (int i = 0; i < writerThreads; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < operationsPerThread; j++) {
                        SecurityEvent event = new SecurityEvent(
                            "write-rule-" + threadId + "-" + j,
                            "input",
                            "/api/test",
                            "GET",
                            "127.0.0.1"
                        );
                        eventRecorder.record(event);
                        writeCount.incrementAndGet();
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        // Reader threads
        for (int i = 0; i < readerThreads; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < operationsPerThread; j++) {
                        eventRecorder.getRecentEvents(10);
                        readCount.incrementAndGet();
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(30, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "All threads should complete within timeout");
        assertEquals(writerThreads * operationsPerThread, writeCount.get(), "All writes should succeed");
        assertEquals(readerThreads * operationsPerThread, readCount.get(), "All reads should succeed");
    }

    // ==================== RuleEngine 并发测试 ====================

    @Test
    @DisplayName("RuleEngine should be thread-safe for concurrent matching")
    void testRuleEngineConcurrentMatch() throws InterruptedException {
        int threadCount = 20;
        int matchesPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger matchCount = new AtomicInteger(0);
        AtomicInteger noMatchCount = new AtomicInteger(0);

        String[] testInputs = {
            "<script>alert(1)</script>",      // XSS - should match
            "UNION SELECT * FROM users",       // SQL - should match
            "normal text input",               // Safe - no match
            "Hello World",                     // Safe - no match
            "../../../etc/passwd",             // Path traversal - should match
            "safe query"                       // Safe - no match
        };

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < matchesPerThread; j++) {
                        String input = testInputs[j % testInputs.length];
                        String result = ruleEngine.match(input);
                        if (result != null) {
                            matchCount.incrementAndGet();
                        } else {
                            noMatchCount.incrementAndGet();
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(30, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "All threads should complete within timeout");
        assertEquals(threadCount * matchesPerThread, matchCount.get() + noMatchCount.get(), 
            "Total operations should match");
        assertTrue(matchCount.get() > 0, "Should have some matches");
        assertTrue(noMatchCount.get() > 0, "Should have some non-matches");
    }

    // ==================== Filter 并发测试 ====================

    @Test
    @DisplayName("Filter should handle concurrent requests safely")
    void testFilterConcurrentRequests() throws InterruptedException {
        int threadCount = 15;
        int requestsPerThread = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger blockedCount = new AtomicInteger(0);
        AtomicInteger allowedCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < requestsPerThread; j++) {
                        try {
                            MockHttpServletRequest request = new MockHttpServletRequest();
                            MockHttpServletResponse response = new MockHttpServletResponse();
                            MockFilterChain chain = new MockFilterChain();

                            // Alternate between safe and malicious requests
                            if ((threadId + j) % 3 == 0) {
                                // Malicious request
                                request.setRequestURI("/api/test");
                                request.setMethod("GET");
                                request.addParameter("q", "<script>alert(1)</script>");
                            } else {
                                // Safe request
                                request.setRequestURI("/api/test");
                                request.setMethod("GET");
                                request.addParameter("name", "user" + threadId);
                            }

                            filter.doFilter(request, response, chain);

                            if (response.getStatus() == 403) {
                                blockedCount.incrementAndGet();
                            } else if (response.getStatus() == 200) {
                                allowedCount.incrementAndGet();
                            }
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(60, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "All threads should complete within timeout");
        assertEquals(0, errorCount.get(), "No errors should occur during concurrent access");
        assertTrue(blockedCount.get() > 0, "Some requests should be blocked");
        assertTrue(allowedCount.get() > 0, "Some requests should be allowed");
        assertEquals(threadCount * requestsPerThread, blockedCount.get() + allowedCount.get(), 
            "Total requests should match");
    }

    @Test
    @DisplayName("Filter should handle concurrent body checks safely")
    void testFilterConcurrentBodyCheck() throws InterruptedException {
        int threadCount = 10;
        int requestsPerThread = 15;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < requestsPerThread; j++) {
                        try {
                            MockHttpServletRequest request = new MockHttpServletRequest();
                            MockHttpServletResponse response = new MockHttpServletResponse();
                            MockFilterChain chain = new MockFilterChain();

                            request.setRequestURI("/api/data");
                            request.setMethod("POST");
                            request.setContentType("application/json");
                            
                            // Create JSON body
                            String json = "{\"id\":" + threadId + ", \"value\":\"test" + j + "\"}";
                            request.setContent(json.getBytes(StandardCharsets.UTF_8));

                            filter.doFilter(request, response, chain);
                            successCount.incrementAndGet();
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(60, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "All threads should complete within timeout");
        assertEquals(0, errorCount.get(), "No errors should occur during concurrent body checks");
        assertEquals(threadCount * requestsPerThread, successCount.get(), "All requests should succeed");
    }

    // ==================== 压力测试 ====================

    @Test
    @DisplayName("Should handle high load without memory issues")
    void testHighLoadMemoryUsage() throws InterruptedException {
        int threadCount = 50;
        int operationsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger totalOperations = new AtomicInteger(0);

        long startTime = System.currentTimeMillis();
        long initialMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < operationsPerThread; j++) {
                        SecurityEvent event = new SecurityEvent(
                            "stress-rule",
                            "stress-input-" + j,
                            "/api/stress",
                            "POST",
                            "127.0.0.1"
                        );
                        eventRecorder.record(event);
                        totalOperations.incrementAndGet();
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(120, TimeUnit.SECONDS);
        executor.shutdown();

        long endTime = System.currentTimeMillis();
        long finalMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long memoryIncrease = finalMemory - initialMemory;

        assertTrue(completed, "All threads should complete within timeout");
        assertEquals(threadCount * operationsPerThread, totalOperations.get(), 
            "All operations should complete");
        
        System.out.println("=== Stress Test Results ===");
        System.out.println("Total operations: " + totalOperations.get());
        System.out.println("Time taken: " + (endTime - startTime) + "ms");
        System.out.println("Operations per second: " + 
            (totalOperations.get() * 1000 / (endTime - startTime)));
        System.out.println("Memory increase: " + (memoryIncrease / 1024 / 1024) + "MB");
        
        // Memory should not grow excessively (less than 100MB for this test)
        assertTrue(memoryIncrease < 100 * 1024 * 1024, 
            "Memory should not grow excessively during stress test");
    }

    @Test
    @DisplayName("Should maintain performance under sustained load")
    void testSustainedLoadPerformance() throws InterruptedException {
        int iterations = 1000;
        long totalTime = 0;
        
        for (int i = 0; i < iterations; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setRequestURI("/api/test");
            request.setMethod("GET");
            request.addParameter("name", "user" + i);
            
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            
            long start = System.nanoTime();
            try {
                filter.doFilter(request, response, chain);
            } catch (Exception e) {
                fail("Should not throw exception: " + e.getMessage());
            }
            totalTime += System.nanoTime() - start;
        }
        
        double avgTimeMs = totalTime / iterations / 1_000_000.0;
        System.out.println("=== Performance Test Results ===");
        System.out.println("Total iterations: " + iterations);
        System.out.println("Average time per request: " + String.format("%.3f", avgTimeMs) + "ms");
        System.out.println("Requests per second: " + String.format("%.0f", 1000 / avgTimeMs));
        
        // Average time should be less than 5ms per request
        assertTrue(avgTimeMs < 5.0, "Average request time should be less than 5ms");
    }

    // ==================== 辅助方法 ====================

    private List<SecurityRule> createTestRules() {
        List<SecurityRule> rules = new ArrayList<>();
        
        rules.add(createRule("xss-attack", 
            "(?i)(<\\s*script[^>]*>|</\\s*script\\s*>|on\\w+\\s*=|javascript:)", 
            "high", true));
        
        rules.add(createRule("sql-injection", 
            "(?i)\\bunion\\s+(?:all\\s+)?select\\b", 
            "high", true));
        
        rules.add(createRule("command-injection", 
            "(?i)(;|\\||&|`|\\$\\(|\\$\\{)", 
            "high", true));
        
        rules.add(createRule("path-traversal", 
            "(?i)(\\.\\.[/\\\\])", 
            "high", true));
        
        return rules;
    }

    private SecurityRule createRule(String name, String pattern, String level, boolean enabled) {
        SecurityRule rule = new SecurityRule();
        rule.setName(name);
        rule.setPattern(pattern);
        rule.setLevel(level);
        rule.setEnabled(enabled);
        return rule;
    }
}
