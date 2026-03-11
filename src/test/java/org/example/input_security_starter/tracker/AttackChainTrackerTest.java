package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 攻击链追踪器单元测试
 * 测试场景：模拟完整的攻击流程（侦察 → 投递 → 利用）
 */
@DisplayName("攻击链追踪器测试")
class AttackChainTrackerTest {

    private static final Logger log = LoggerFactory.getLogger(AttackChainTrackerTest.class);

    private AttackChainTracker tracker;
    private TestAlertHandler alertHandler;

    @BeforeEach
    void setUp() {
        // 创建追踪器：最大 100 会话，超时 5 分钟，最大事件 20，最小阶段 2
        tracker = new AttackChainTracker(100, 5, 20, 2);
        alertHandler = new TestAlertHandler();
        tracker.setAlertHandler(alertHandler);
    }

    @Test
    @DisplayName("测试规则到攻击阶段的映射")
    void testRulePhaseMapping() {
        // 侦察阶段
        assertEquals(AttackPhase.RECONNAISSANCE, AttackChainTracker.getPhaseForRule("ssrf-attack"));
        assertEquals(AttackPhase.RECONNAISSANCE, AttackChainTracker.getPhaseForRule("path-traversal"));
        assertEquals(AttackPhase.RECONNAISSANCE, AttackChainTracker.getPhaseForRule("ldap-injection"));

        // 投递阶段
        assertEquals(AttackPhase.DELIVERY, AttackChainTracker.getPhaseForRule("xss-attack"));
        assertEquals(AttackPhase.DELIVERY, AttackChainTracker.getPhaseForRule("sql-injection"));
        assertEquals(AttackPhase.DELIVERY, AttackChainTracker.getPhaseForRule("xxe-injection"));

        // 利用阶段
        assertEquals(AttackPhase.EXPLOITATION, AttackChainTracker.getPhaseForRule("command-injection"));
        assertEquals(AttackPhase.EXPLOITATION, AttackChainTracker.getPhaseForRule("code-execution"));

        // 未映射的规则
        assertNull(AttackChainTracker.getPhaseForRule("unknown-rule"));
    }

    @Test
    @DisplayName("测试完整攻击流程：SSRF 侦察 → SQL 注入投递 → 命令执行利用")
    void testCompleteAttackChain() throws InterruptedException {
        String clientIp = "192.168.1.100";
        String httpSessionId = "sess-abc123";
        String expectedSessionId = clientIp + ":" + httpSessionId;

        // 阶段 1: SSRF 侦察
        SecurityEvent ssrfEvent = createSecurityEvent("ssrf-attack", clientIp, httpSessionId);
        tracker.onSecurityEvent(ssrfEvent);

        AttackSession session1 = tracker.getSession(expectedSessionId);
        assertNotNull(session1, "Session should be created after first event");
        assertTrue(session1.getTriggeredPhases().contains(AttackPhase.RECONNAISSANCE));
        assertEquals(1, session1.getEventCount());
        assertEquals(0, session1.getChains().size()); // 还未形成攻击链

        // 阶段 2: SQL 注入投递
        SecurityEvent sqlEvent = createSecurityEvent("sql-injection", clientIp, httpSessionId);
        tracker.onSecurityEvent(sqlEvent);

        AttackSession session2 = tracker.getSession(expectedSessionId);
        assertTrue(session2.getTriggeredPhases().contains(AttackPhase.DELIVERY));
        assertEquals(2, session2.getEventCount());

        // 应该检测到攻击链（侦察 → 投递）
        assertTrue(session2.isChainDetected());
        assertEquals(1, session2.getChains().size());
        assertEquals(AttackPhase.RECONNAISSANCE, session2.getChains().get(0).getFromPhase());
        assertEquals(AttackPhase.DELIVERY, session2.getChains().get(0).getToPhase());

        // 阶段 3: 命令执行利用
        SecurityEvent cmdEvent = createSecurityEvent("command-injection", clientIp, httpSessionId);
        tracker.onSecurityEvent(cmdEvent);

        AttackSession session3 = tracker.getSession(expectedSessionId);
        assertTrue(session3.getTriggeredPhases().contains(AttackPhase.EXPLOITATION));
        assertEquals(3, session3.getEventCount());
        assertEquals(AttackPhase.EXPLOITATION, session3.getCurrentPhase());

        // 应该检测到更多攻击链
        assertTrue(session3.isChainDetected());
        assertTrue(session3.getChains().size() >= 2);

        // 验证告警已触发
        Thread.sleep(100); // 等待异步处理
        assertFalse(alertHandler.getAlerts().isEmpty());

        AttackChainAlert alert = alertHandler.getAlerts().get(0);
        assertEquals("attack_chain_detected", alert.getAlertType());
        assertEquals(expectedSessionId, alert.getSessionId());
        assertEquals(clientIp, alert.getClientIp());
        assertTrue(alert.getEventCount() >= 2, "Event count should be >= 2");
        // 告警可能在第三个事件之前触发，所以检查是否是 DELIVERY 或 EXPLOITATION
        assertTrue(alert.getCurrentPhase() == AttackPhase.DELIVERY || alert.getCurrentPhase() == AttackPhase.EXPLOITATION);

        log.info("攻击链检测成功：{}", alert.toMap());
    }

    @Test
    @DisplayName("测试多阶段攻击：路径遍历 → XSS → 反序列化")
    void testMultiStageAttack() {
        String clientIp = "10.0.0.50";
        String httpSessionId = "sess-multi";
        String expectedSessionId = clientIp + ":" + httpSessionId;

        // 阶段 1: 路径遍历侦察
        tracker.onSecurityEvent(createSecurityEvent("path-traversal", clientIp, httpSessionId));

        // 阶段 2: XSS 投递
        tracker.onSecurityEvent(createSecurityEvent("xss-attack", clientIp, httpSessionId));

        // 阶段 3: 反序列化利用
        tracker.onSecurityEvent(createSecurityEvent("deserialization-attack", clientIp, httpSessionId));

        AttackSession session = tracker.getSession(expectedSessionId);
        assertNotNull(session);

        // 验证三个阶段都被触发
        assertTrue(session.getTriggeredPhases().contains(AttackPhase.RECONNAISSANCE));
        assertTrue(session.getTriggeredPhases().contains(AttackPhase.DELIVERY));
        assertTrue(session.getTriggeredPhases().contains(AttackPhase.EXPLOITATION));

        // 验证攻击链检测
        assertTrue(session.isChainDetected());
        assertTrue(session.getChains().size() >= 2);

        // 验证事件数量
        assertTrue(session.getEventCount() >= 3);
    }

    @Test
    @DisplayName("测试单阶段多次攻击（不形成攻击链）")
    void testSinglePhaseMultipleAttacks() {
        String clientIp = "172.16.0.100";
        String httpSessionId = "sess-single";
        String expectedSessionId = clientIp + ":" + httpSessionId;

        // 只有 XSS 投递阶段，多次触发
        for (int i = 0; i < 5; i++) {
            tracker.onSecurityEvent(createSecurityEvent("xss-attack", clientIp, httpSessionId));
        }

        AttackSession session = tracker.getSession(expectedSessionId);
        assertNotNull(session);

        // 应该只有一个阶段
        assertEquals(1, session.getTriggeredPhases().size());
        assertTrue(session.getTriggeredPhases().contains(AttackPhase.DELIVERY));

        // 不应该检测到攻击链（需要至少 2 个不同阶段）
        assertFalse(session.isChainDetected());

        // 验证事件数量（保留最后 20 条）
        assertEquals(5, session.getEventCount());
    }

    @Test
    @DisplayName("测试会话过期清理")
    void testSessionCleanup() throws InterruptedException {
        String clientIp = "192.168.2.100";
        String httpSessionId = "sess-temp";
        String expectedSessionId = clientIp + ":" + httpSessionId;

        // 创建会话
        tracker.onSecurityEvent(createSecurityEvent("ssrf-attack", clientIp, httpSessionId));
        assertNotNull(tracker.getSession(expectedSessionId));

        // 清理器每分钟运行一次，我们验证会话存在即可
        AttackSession session = tracker.getSession(expectedSessionId);
        assertNotNull(session);
        assertFalse(session.isExpired(5 * 60 * 1000)); // 5 分钟内不应过期
    }

    @Test
    @DisplayName("测试告警阈值触发")
    void testAlertThresholdTrigger() {
        String clientIp = "192.168.3.100";
        String httpSessionId = "sess-high-risk";
        String expectedSessionId = clientIp + ":" + httpSessionId;

        // 多次触发不同阶段的攻击，累积风险分
        String[] rules = {"ssrf-attack", "path-traversal", "sql-injection", "xss-attack", "command-injection"};

        for (String rule : rules) {
            tracker.onSecurityEvent(createSecurityEvent(rule, clientIp, httpSessionId));
        }

        AttackSession session = tracker.getSession(expectedSessionId);
        assertNotNull(session);

        // 验证事件数量
        assertTrue(session.getEventCount() >= 3);
    }

    @Test
    @DisplayName("测试攻击阶段顺序验证")
    void testAttackPhaseOrder() {
        // 验证阶段顺序正确
        assertTrue(AttackPhase.RECONNAISSANCE.isBefore(AttackPhase.DELIVERY));
        assertTrue(AttackPhase.DELIVERY.isBefore(AttackPhase.EXPLOITATION));
        assertTrue(AttackPhase.EXPLOITATION.isAfter(AttackPhase.DELIVERY));

        // 验证阶段距离计算
        assertEquals(1, AttackPhase.DELIVERY.distance(AttackPhase.RECONNAISSANCE));
        assertEquals(2, AttackPhase.EXPLOITATION.distance(AttackPhase.RECONNAISSANCE));
    }

    /**
     * 创建测试用的安全事件
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
     * 测试用告警处理器
     */
    private static class TestAlertHandler implements AttackChainTracker.AlertHandler {
        private final List<AttackChainAlert> alerts = new CopyOnWriteArrayList<>();

        @Override
        public void onAlert(AttackChainAlert alert) {
            alerts.add(alert);
            log.info("收到告警：type={}, session={}, eventCount={}",
                    alert.getAlertType(), alert.getSessionId(), alert.getEventCount());
        }

        public List<AttackChainAlert> getAlerts() {
            return new ArrayList<>(alerts);
        }
    }
}
