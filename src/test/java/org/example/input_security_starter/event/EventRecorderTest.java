package org.example.input_security_starter.event;

import org.example.input_security_starter.tracker.AttackChainAlert;
import org.example.input_security_starter.tracker.AttackChainTracker;
import org.example.input_security_starter.tracker.AttackPhase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 事件记录器双日志系统单元测试
 * 验证：
 * 1. 普通安全事件写入 security-events.log
 * 2. 攻击链告警写入 attack-chain-alerts.log
 */
@DisplayName("双日志系统测试")
class EventRecorderTest {

    private static final Logger log = LoggerFactory.getLogger(EventRecorderTest.class);

    private static final String TEST_EVENT_LOG = "test-security-events.log";
    private static final String TEST_ALERT_LOG = "attack-chain-alerts.log";

    private EventRecorder eventRecorder;
    private AttackChainTracker attackChainTracker;

    @BeforeEach
    void setUp() {
        // 清理测试日志文件
        cleanupTestFiles();
        
        // 创建事件记录器（使用同步模式）
        eventRecorder = new EventRecorder(TEST_EVENT_LOG, 10, 3, false);
        
        // 创建攻击链追踪器
        attackChainTracker = new AttackChainTracker(100, 5, 20, 2);
        
        // 设置告警处理器 - 将告警写入文件
        attackChainTracker.setAlertHandler(alert -> {
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                String json = mapper.writeValueAsString(alert.toMap());
                try (java.io.BufferedWriter writer = new java.io.BufferedWriter(new java.io.FileWriter(TEST_ALERT_LOG, true))) {
                    writer.write(json);
                    writer.newLine();
                }
                log.info("Alert written to file: {}", alert.getAlertType());
            } catch (Exception e) {
                log.error("Failed to write alert: {}", e.getMessage());
            }
        });
        
        eventRecorder.setAttackChainTracker(attackChainTracker);
    }

    @AfterEach
    void tearDown() {
        if (eventRecorder != null) {
            eventRecorder.shutdown();
        }
        // 延迟清理，让测试完成
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        cleanupTestFiles();
    }

    @Test
    @DisplayName("测试普通安全事件写入日志")
    void testSecurityEventLogging() throws Exception {
        // 创建安全事件
        SecurityEvent event = new SecurityEvent.Builder("xss-attack", "<script>alert(1)</script>", "/api/test", "GET")
                .ipAddress("192.168.1.100")
                .sessionId("test-session-1")
                .originalInput("<script>alert(1)</script>")
                .normalizedInput("<script>alert(1)</script>")
                .inputSource("parameter")
                .parameterName("q")
                .ruleLevel("high")
                .build();

        // 记录事件
        eventRecorder.record(event);

        // 同步模式，立即验证
        File logFile = new File(getDatedLogFileName(TEST_EVENT_LOG));
        assertTrue(logFile.exists(), "Security event log file should exist");

        // 验证日志内容
        String logContent = readLogFile(logFile);
        assertTrue(logContent.contains("xss-attack"), "Log should contain rule name");
        assertTrue(logContent.contains("192.168.1.100"), "Log should contain IP address");
        assertTrue(logContent.contains("<script>alert(1)</script>"), "Log should contain payload");
        assertTrue(logContent.contains("parameter"), "Log should contain input source");

        log.info("普通安全事件日志测试通过");
    }

    @Test
    @DisplayName("测试攻击链告警写入独立日志")
    void testAttackChainAlertLogging() throws Exception {
        // 模拟多阶段攻击，触发攻击链告警
        String clientIp = "10.0.0.50";
        String sessionId = "test-session-2";

        // 阶段 1: 侦察
        SecurityEvent ssrfEvent = createSecurityEvent("ssrf-attack", clientIp, sessionId);
        eventRecorder.record(ssrfEvent);

        // 阶段 2: 投递
        SecurityEvent sqlEvent = createSecurityEvent("sql-injection", clientIp, sessionId);
        eventRecorder.record(sqlEvent);

        // 阶段 3: 利用
        SecurityEvent cmdEvent = createSecurityEvent("command-injection", clientIp, sessionId);
        eventRecorder.record(cmdEvent);

        // 同步模式，立即验证
        File eventLogFile = new File(getDatedLogFileName(TEST_EVENT_LOG));
        assertTrue(eventLogFile.exists(), "Event log file should exist");

        // 验证告警日志文件存在
        File alertLogFile = new File(TEST_ALERT_LOG);
        assertTrue(alertLogFile.exists(), "Attack chain alert log file should exist");

        // 验证告警日志内容
        String alertContent = readLogFile(alertLogFile);
        assertTrue(alertContent.contains("attack_chain_detected"), "Alert log should contain alert type");
        assertTrue(alertContent.contains("attack_chains"), "Alert log should contain attack chains");
        assertTrue(alertContent.contains("events"), "Alert log should contain events");
        assertTrue(alertContent.contains(clientIp), "Alert log should contain client IP");

        log.info("攻击链告警日志测试通过");
        log.info("告警内容：{}", alertContent.substring(0, Math.min(500, alertContent.length())));
    }

    @Test
    @DisplayName("测试单阶段攻击不触发告警日志")
    void testSinglePhaseNoAlert() throws Exception {
        String clientIp = "172.16.0.100";
        String sessionId = "test-session-3";

        // 只有单阶段攻击（XSS），不应触发攻击链告警
        for (int i = 0; i < 3; i++) {
            SecurityEvent event = createSecurityEvent("xss-attack", clientIp, sessionId);
            eventRecorder.record(event);
        }

        // 同步模式，立即验证
        File eventLogFile = new File(getDatedLogFileName(TEST_EVENT_LOG));
        assertTrue(eventLogFile.exists(), "Event log file should exist");

        // 验证告警日志不存在或为空（因为单阶段不形成攻击链）
        File alertLogFile = new File(TEST_ALERT_LOG);
        if (alertLogFile.exists()) {
            String alertContent = readLogFile(alertLogFile);
            // 单阶段攻击不应该触发攻击链告警
            // 但可能触发高风险评分告警（多次攻击累积高分）
            // 所以我们检查是否不包含 attack_chain_detected
            assertFalse(alertContent.contains("attack_chain_detected") && alertContent.contains(clientIp), 
                "Single phase attack should not trigger attack_chain_detected alert");
        }

        log.info("单阶段攻击不触发告警测试通过");
    }

    @Test
    @DisplayName("测试日志格式正确性")
    void testLogFormatValidity() throws Exception {
        // 创建事件
        SecurityEvent event = createSecurityEvent("sql-injection", "192.168.5.100", "test-session-4");
        eventRecorder.record(event);

        // 同步模式，立即验证
        File logFile = new File(getDatedLogFileName(TEST_EVENT_LOG));
        String logContent = readLogFile(logFile);

        // 验证 JSON 格式（每行是一个 JSON 对象）
        String[] lines = logContent.split("\n");
        assertTrue(lines.length > 0, "Log should have at least one line");

        // 验证第一行是有效的 JSON
        String firstLine = lines[0].trim();
        assertTrue(firstLine.startsWith("{") && firstLine.endsWith("}"), 
            "Each log line should be a JSON object");

        // 验证必需字段
        assertTrue(firstLine.contains("\"ts\""), "Log should contain timestamp");
        assertTrue(firstLine.contains("\"rule\""), "Log should contain rule name");
        assertTrue(firstLine.contains("\"ip\""), "Log should contain IP");
        assertTrue(firstLine.contains("\"url\""), "Log should contain URL");

        log.info("日志格式验证通过");
    }

    @Test
    @DisplayName("测试攻击链告警包含完整上下文")
    void testAttackChainAlertContext() throws Exception {
        String clientIp = "192.168.10.50";
        String sessionId = "test-session-5";

        // 触发完整攻击链
        eventRecorder.record(createSecurityEvent("path-traversal", clientIp, sessionId));
        eventRecorder.record(createSecurityEvent("xss-attack", clientIp, sessionId));
        eventRecorder.record(createSecurityEvent("deserialization-attack", clientIp, sessionId));

        // 同步模式，立即验证
        File alertLogFile = new File(TEST_ALERT_LOG);
        assertTrue(alertLogFile.exists(), "Alert log should exist");

        String alertContent = readLogFile(alertLogFile);

        // 验证告警包含攻击链信息（至少包含侦察和投递阶段）
        assertTrue(alertContent.contains("\"triggered_phases\""), "Should contain triggered phases");
        assertTrue(alertContent.contains("\"attack_chains\""), "Should contain attack chains");
        assertTrue(alertContent.contains("\"events\""), "Should contain events");
        assertTrue(alertContent.contains("\"payload_preview\""), "Should contain payload preview");

        // 验证阶段信息（告警触发时至少有侦察和投递阶段）
        assertTrue(alertContent.contains("reconnaissance"), "Should contain reconnaissance phase");
        assertTrue(alertContent.contains("delivery"), "Should contain delivery phase");

        log.info("攻击链告警上下文完整性测试通过");
    }

    /**
     * 创建测试用安全事件
     */
    private SecurityEvent createSecurityEvent(String ruleName, String clientIp, String sessionId) {
        return new SecurityEvent.Builder(ruleName, "test-payload", "/api/test", "GET")
                .ipAddress(clientIp)
                .sessionId(sessionId)
                .originalInput("malicious-input")
                .normalizedInput("malicious-input")
                .inputSource("parameter")
                .parameterName("q")
                .ruleLevel("high")
                .build();
    }

    /**
     * 获取带日期的日志文件名
     */
    private String getDatedLogFileName(String baseName) {
        String date = new java.text.SimpleDateFormat("yyyy-MM-dd").format(new java.util.Date());
        if (baseName.contains(".")) {
            int dotIndex = baseName.lastIndexOf(".");
            return baseName.substring(0, dotIndex) + "-" + date + baseName.substring(dotIndex);
        }
        return baseName + "-" + date + ".log";
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
        deleteFile(TEST_EVENT_LOG);
        deleteFile(TEST_ALERT_LOG);
        deleteFile(getDatedLogFileName(TEST_EVENT_LOG));
    }

    /**
     * 删除文件（如果存在）
     */
    private void deleteFile(String fileName) {
        try {
            File file = new File(fileName);
            if (file.exists()) {
                Files.delete(file.toPath());
            }
            // 也尝试删除带日期的变体
            File datedFile = new File(getDatedLogFileName(fileName));
            if (datedFile.exists()) {
                Files.delete(datedFile.toPath());
            }
        } catch (IOException e) {
            log.warn("Failed to delete test file: {}", fileName);
        }
    }
}
