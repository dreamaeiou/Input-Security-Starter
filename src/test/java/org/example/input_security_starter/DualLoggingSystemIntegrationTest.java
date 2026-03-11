package org.example.input_security_starter;

import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.event.SecurityEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 双日志系统集成测试
 * 验证 Spring 环境下的完整日志功能：
 * 1. 普通安全事件写入 security-events.log
 * 2. 攻击链告警写入 attack-chain-alerts.log
 */
@SpringBootTest(
    classes = InputSecuritySdkApplication.class,
    properties = {
        "input-security.enabled=true",
        "input-security.attack-chain.enabled=true",
        "input-security.attack-chain.alert-threshold=60",
        "input-security.attack-chain.min-phases-for-chain=3",
        "input-security.log-file-path=target/test-integration-security-events.log",
        "input-security.attack-chain.alert-log-path=target/test-integration-attack-chain-alerts.log",
        "input-security.async-log-enabled=false"
    }
)
@DisplayName("双日志系统集成测试")
class DualLoggingSystemIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(DualLoggingSystemIntegrationTest.class);
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    @Autowired
    private EventRecorder eventRecorder;

    @BeforeEach
    void setUp() {
        cleanupTestFiles();
    }

    @AfterEach
    void tearDown() {
        cleanupTestFiles();
    }

    @Test
    @DisplayName("测试多阶段攻击触发双日志写入")
    void testMultiStageAttackDualLogging() throws Exception {
        String clientIp = "192.168.100.50";
        String sessionId = "integration-test-session";

        // 阶段 1: 侦察（SSRF）
        SecurityEvent ssrfEvent = createSecurityEvent("ssrf-attack", clientIp, sessionId, "/api/proxy", "GET");
        eventRecorder.record(ssrfEvent);

        // 阶段 2: 投递（SQL 注入）
        SecurityEvent sqlEvent = createSecurityEvent("sql-injection", clientIp, sessionId, "/api/search", "POST");
        eventRecorder.record(sqlEvent);

        // 阶段 3: 利用（命令注入）
        SecurityEvent cmdEvent = createSecurityEvent("command-injection", clientIp, sessionId, "/api/admin", "POST");
        eventRecorder.record(cmdEvent);

        // 等待处理完成
        Thread.sleep(500);

        // 验证普通事件日志
        File eventLogFile = new File(getEventLogPathForToday());
        assertTrue(eventLogFile.exists(), "Security event log file should exist");

        String eventLogContent = readLogFile(eventLogFile);
        assertTrue(eventLogContent.contains("ssrf-attack"), "Event log should contain SSRF attack");
        assertTrue(eventLogContent.contains("sql-injection"), "Event log should contain SQL injection");
        assertTrue(eventLogContent.contains("command-injection"), "Event log should contain command injection");
        assertTrue(eventLogContent.contains(clientIp), "Event log should contain client IP");

        log.info("普通事件日志验证通过，共 {} 条记录", eventLogContent.split("\n").length);

        // 验证告警日志文件存在
        File alertLogFile = new File("target/test-integration-attack-chain-alerts.log");
        assertTrue(alertLogFile.exists(), "Attack chain alert log file should exist");

        String alertLogContent = readLogFile(alertLogFile);
        assertTrue(alertLogContent.contains("attack_chain_detected"), "Alert log should contain alert type");
        assertTrue(alertLogContent.contains("attack_chains"), "Alert log should contain attack chains");
        assertTrue(alertLogContent.contains("events"), "Alert log should contain events");
        assertTrue(alertLogContent.contains(clientIp), "Alert log should contain client IP");
        assertTrue(alertLogContent.contains("reconnaissance"), "Alert log should contain reconnaissance phase");
        assertTrue(alertLogContent.contains("delivery"), "Alert log should contain delivery phase");
        assertTrue(alertLogContent.contains("exploitation"), "Alert log should contain exploitation phase");

        log.info("攻击链告警日志验证通过");
        log.info("告警内容预览：{}", alertLogContent.substring(0, Math.min(500, alertLogContent.length())));
    }

    @Test
    @DisplayName("测试单阶段攻击只写入普通日志")
    void testSinglePhaseOnlyEventLog() throws Exception {
        String clientIp = "10.20.30.40";
        String sessionId = "single-phase-session";

        // 只有单阶段攻击（XSS），不应触发攻击链告警
        for (int i = 0; i < 3; i++) {
            SecurityEvent event = createSecurityEvent("xss-attack", clientIp, sessionId, "/api/comment", "POST");
            eventRecorder.record(event);
        }

        Thread.sleep(500);

        // 验证普通事件日志存在
        File eventLogFile = new File(getEventLogPathForToday());
        assertTrue(eventLogFile.exists(), "Event log file should exist");

        String eventLogContent = readLogFile(eventLogFile);
        assertTrue(eventLogContent.contains("xss-attack"), "Event log should contain XSS attacks");
        assertEquals(3, eventLogContent.split("\n").length, "Should have 3 XSS events");

        // 验证告警日志不存在或不包含本次会话
        File alertLogFile = new File("target/test-integration-attack-chain-alerts.log");
        if (alertLogFile.exists()) {
            String alertContent = readLogFile(alertLogFile);
            assertFalse(alertContent.contains(clientIp), 
                "Single phase attack should not trigger alert for this session");
        }

        log.info("单阶段攻击只写入普通日志测试通过");
    }

    @Test
    @DisplayName("测试告警日志包含完整攻击链上下文")
    void testAlertLogCompleteContext() throws Exception {
        String clientIp = "172.16.50.100";
        String sessionId = "full-context-session";

        // 触发完整攻击链
        eventRecorder.record(createSecurityEvent("path-traversal", clientIp, sessionId, "/api/file", "GET"));
        eventRecorder.record(createSecurityEvent("xss-attack", clientIp, sessionId, "/api/profile", "POST"));
        eventRecorder.record(createSecurityEvent("deserialization-attack", clientIp, sessionId, "/api/data", "POST"));

        Thread.sleep(500);

        // 读取告警日志
        File alertLogFile = new File("target/test-integration-attack-chain-alerts.log");
        assertTrue(alertLogFile.exists(), "Alert log should exist");

        String alertContent = readLogFile(alertLogFile);

        // 验证告警包含完整信息
        assertTrue(alertContent.contains("\"triggered_phases\""), "Should contain triggered phases");
        assertTrue(alertContent.contains("\"attack_chains\""), "Should contain attack chains");
        assertTrue(alertContent.contains("\"events\""), "Should contain events");
        assertTrue(alertContent.contains("\"payload_preview\""), "Should contain payload preview");

        // 验证攻击链信息
        assertTrue(alertContent.contains("path-traversal"), "Should contain path-traversal rule");
        assertTrue(alertContent.contains("xss-attack"), "Should contain xss-attack rule");
        assertTrue(alertContent.contains("deserialization-attack"), "Should contain deserialization-attack rule");

        log.info("告警日志完整上下文验证通过");
    }

    /**
     * 创建测试用安全事件
     */
    private SecurityEvent createSecurityEvent(String ruleName, String clientIp, String sessionId, 
                                               String url, String method) {
        return new SecurityEvent.Builder(ruleName, "test-payload", url, method)
                .ipAddress(clientIp)
                .sessionId(sessionId)
                .originalInput("malicious-input-" + System.currentTimeMillis())
                .normalizedInput("malicious-input")
                .inputSource("parameter")
                .parameterName("q")
                .ruleLevel("high")
                .build();
    }

    /**
     * 读取日志文件内容
     */
    private String readLogFile(File file) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }

    /**
     * 清理测试日志文件
     */
    private void cleanupTestFiles() {
        deleteFile(getEventLogPathForToday());
        deleteFile("target/test-integration-attack-chain-alerts.log");
    }

    private String getEventLogPathForToday() {
        return "target/test-integration-security-events-" + LocalDate.now().format(DATE_FMT) + ".log";
    }

    /**
     * 删除文件（如果存在）
     */
    private void deleteFile(String fileName) {
        try {
            File file = new File(fileName);
            if (file.exists()) {
                Files.delete(file.toPath());
                log.debug("Deleted test file: {}", fileName);
            }
        } catch (IOException e) {
            log.warn("Failed to delete test file: {}", fileName, e);
        }
    }
}
