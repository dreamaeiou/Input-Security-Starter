package org.example.input_security_starter.config;

import org.example.input_security_starter.model.SecurityRule;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "input-security")
public class InputSecurityProperties {

    private boolean enabled = true;
    private Mode mode = Mode.MONITOR;
    private List<SecurityRule> rules = new ArrayList<>();

    public enum Mode {
        MONITOR,  // 监控模式
        BLOCK  // 拦截模式
    }

    public List<SecurityRule> getRules() {
        if (rules.isEmpty()) {
            // 提供默认规则（fallback）

            // XSS 攻击规则 - 统一归类
            rules.add(createRule(
                    "xss-attack",
                    "(?i)(<\\s*script[^>]*>|</\\s*script\\s*>|on(load|error|focus|blur|click|dblclick|mousedown|mouseup|mouseover|mousemove|mouseout|keydown|keypress|keyup|submit|reset|change|select)\\s*=|javascript:\\s*|vbscript:\\s*|data:\\s*text/html|<\\s*svg[^>]*>.*<\\s*script|<\\s*img[^>]+src\\s*=\\s*['\"]?\\s*javascript:|<\\s*object[^>]*>|<\\s*embed[^>]*>|expression\\s*\\(|<\\s*meta[^>]+refresh[^>]*>|<\\s*import[^>]*>|<\\s*base[^>]+href[^>]*>|<\\s*iframe[^>]*>|<\\s*form[^>]+action\\s*=\\s*['\"]?\\s*javascript:|<\\s*style[^>]*>.*expression\\s*\\(|<\\s*link[^>]*rel\\s*=\\s*['\"]?stylesheet['\"]?[^>]*href\\s*=\\s*['\"]?javascript:|<\\s*body[^>]*onload\\s*=|background-image\\s*:.*url\\s*\\()",
                    "high",
                    true));

            // 代码执行规则 - 统一归类 (放在SQL注入之前以确保优先匹配)
            rules.add(createRule(
                    "code-execution",
                    "(?i)\\b(eval|setTimeout|setInterval|system|exec|shell_exec|passthru|popen|proc_open|file_get_contents|fopen|fwrite|fread|readfile)\\s*\\(",
                    "high",
                    true));

            // SQL 注入规则 - 统一归类
            rules.add(createRule(
                    "sql-injection",
                    "\\bunion\\s+(?:all\\s+)?select\\b|\\bselect\\s+[^;]+?\\s+from\\b|\\bexec(?:ute)?\\s+\\w+|\\bdrop\\s+table\\b|\\bcreate\\s+table\\b|\\binsert\\s+into\\b|\\bupdate\\s+\\w+[^;]*?\\s+set\\b|\\bdelete\\s+from\\b|'\\s+(?:--|#|/\\*)|\\b(?:sleep|benchmark)\\s*\\(|`[^`]*['\"][^`]*`|\\b0x[0-9a-fA-F]+\\b|\\bchar\\s*\\([^)]*\\)|\\bcast\\s*\\([^)]*\\s+as\\s+nvarchar\\b\n",
                    "high",
                    true));

            // 命令注入规则 - 统一归类
            rules.add(createRule(
                    "command-injection",
                    "(?i)(?:^|[|&;`]|&&|\\|\\|)\\s*(rm|del|mv|cp|mkdir|touch|echo|cat|ls|dir|ps|kill|ifconfig|ipconfig|wget|curl|nc|netcat|ping)\\b|\\b(rm|del|mv|cp|mkdir|touch|echo|cat|ls|dir|ps|kill|ifconfig|ipconfig|wget|curl|nc|netcat|ping)\\b(?:\\s+[^\\s|&;`]*)*\\s*(?:$|[|&;`]|&&|\\|\\|)\n",
                    "high",
                    true));

            // SSRF相关 - 统一归类
            rules.add(createRule(
                    "ssrf-attack",
                    "(?i)\\b(URLConnection|HttpClient|curl|wget)\\b|file://|[\\\\./]*(etc|windows|winnt)[\\\\./]+passwd",
                    "medium",
                    true));

            // 路径遍历规则 - 统一归类
            rules.add(createRule(
                    "path-traversal",
                    "(?i)((\\.\\.[/\\\\])|(\\.\\.[/\\\\])|(\\.\\.[/\\\\])|(%2e|%2e%2e|%c0%ae|%uff0e|%uff0e%uff0e))",
                    "high",
                    true));

            // LDAP注入规则 - 统一归类
            rules.add(createRule(
                    "ldap-injection",
                    "(?i)(\\([^)]*(?:\\||&|\\*).*\\)|\\*.*\\))",
                    "medium",
                    true));

            // XXE注入规则 - 统一归类
            rules.add(createRule(
                    "xxe-injection",
                    "(?i)(<!\\s*entity\\s|<!\\s*doctype\\s)",
                    "high",
                    true));
        }
        return new ArrayList<>(rules); // 返回副本以防止外部修改
    }

    private SecurityRule createRule(String name, String pattern, String level, boolean enabled) {
        SecurityRule rule = new SecurityRule();
        rule.setName(name);
        rule.setPattern(pattern);
        rule.setLevel(level);
        rule.setEnabled(enabled);
        return rule;
    }

    // 其他 getter/setter
    public boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    public Mode getMode() { return mode; }
    public void setMode(Mode mode) { this.mode = mode; }
    public void setRules(List<SecurityRule> rules) {
        this.rules = rules;
    }
}