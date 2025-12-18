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
            
            // XSS 攻击规则
            rules.add(createRule(
                    "xss-script-tag",
                    "(?i)(<\\s*script[^>]*>|</\\s*script\\s*>)",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-on-event",
                    "(?i)on(load|error|focus|blur|click|dblclick|mousedown|mouseup|mouseover|mousemove|mouseout|keydown|keypress|keyup|submit|reset|change|select)\\s*=\\s*['\"]?[^\\s>]",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-javascript-uri",
                    "(?i)javascript:\\s*[^\"]",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-vbscript-uri",
                    "(?i)vbscript:\\s*[^\"]",
                    "medium",
                    true));
            rules.add(createRule(
                    "xss-data-uri",
                    "(?i)data:\\s*text/html",
                    "medium",
                    true));
            rules.add(createRule(
                    "xss-svg-script",
                    "(?i)<\\s*svg[^>]*>.*<\\s*script",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-img-src-xss",
                    "(?i)<\\s*img[^>]+src\\s*=\\s*['\"]?\\s*javascript:",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-object-tag",
                    "(?i)<\\s*object[^>]*>",
                    "medium",
                    true));
            rules.add(createRule(
                    "xss-embed-tag",
                    "(?i)<\\s*embed[^>]*>",
                    "medium",
                    true));
            rules.add(createRule(
                    "xss-expression",
                    "(?i)expression\\s*\\(",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-meta-refresh",
                    "(?i)<\\s*meta[^>]+refresh[^>]*>",
                    "medium",
                    true));
            rules.add(createRule(
                    "xss-import-statement",
                    "(?i)<\\s*import[^>]*>",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-base-href",
                    "(?i)<\\s*base[^>]+href[^>]*>",
                    "medium",
                    true));
            rules.add(createRule(
                    "xss-iframe-tag",
                    "(?i)<\\s*iframe[^>]*>",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-form-action",
                    "(?i)<\\s*form[^>]+action\\s*=\\s*['\"]?\\s*javascript:",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-style-tag",
                    "(?i)<\\s*style[^>]*>.*expression\\s*\\(",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-link-tag",
                    "(?i)<\\s*link[^>]*rel\\s*=\\s*['\"]?stylesheet['\"]?[^>]*href\\s*=\\s*['\"]?javascript:",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-body-tag",
                    "(?i)<\\s*body[^>]*onload\\s*=",
                    "high",
                    true));
            rules.add(createRule(
                    "xss-background-prop",
                    "(?i)background-image\\s*:.*url\\s*\\(",
                    "medium",
                    true));
            
            // SQL 注入规则
            rules.add(createRule(
                    "sql-union-select",
                    "(?i)(union\\s+(all\\s*)?select|select\\s+.*from)",
                    "high",
                    true));
            rules.add(createRule(
                    "sql-exec",
                    "(?i)(exec|execute)\\s+.*",
                    "high",
                    true));
            rules.add(createRule(
                    "sql-drop-table",
                    "(?i)drop\\s+table",
                    "high",
                    true));
            rules.add(createRule(
                    "sql-create-table",
                    "(?i)create\\s+table",
                    "medium",
                    true));
            rules.add(createRule(
                    "sql-insert-into",
                    "(?i)insert\\s+into\\s+.*",
                    "medium",
                    true));
            rules.add(createRule(
                    "sql-update-set",
                    "(?i)update\\s+.*\\s+set\\s+.*",
                    "medium",
                    true));
            rules.add(createRule(
                    "sql-delete-from",
                    "(?i)delete\\s+from\\s+.*",
                    "high",
                    true));
            rules.add(createRule(
                    "sql-comment",
                    "(?i)'\\s*(--|#|/\\*|\\*/)",
                    "medium",
                    true));
            rules.add(createRule(
                    "sql-sleep",
                    "(?i)sleep\\s*\\(",
                    "high",
                    true));
            rules.add(createRule(
                    "sql-benchmark",
                    "(?i)benchmark\\s*\\(",
                    "high",
                    true));
            rules.add(createRule(
                    "sql-backtick-injection",
                    "(?i)`[^`]*('|\\\")[^`]*`",
                    "high",
                    true));
            rules.add(createRule(
                    "sql-hex-injection",
                    "(?i)0x[0-9a-fA-F]+",
                    "medium",
                    true));
            rules.add(createRule(
                    "sql-char-injection",
                    "(?i)char\\s*\\([^)]*\\)",
                    "medium",
                    true));
            rules.add(createRule(
                    "sql-nvarchar-cast",
                    "(?i)cast\\s*\\([^)]*\\s+as\\s+nvarchar",
                    "high",
                    true));
            
            // 代码执行规则
            rules.add(createRule(
                    "eval-js",
                    "(?i)\\b(eval|setTimeout|setInterval)\\s*\\(",
                    "medium",
                    true));
            rules.add(createRule(
                    "system-command",
                    "(?i)\\b(system|exec|shell_exec|passthru|popen|proc_open)\\s*\\(",
                    "high",
                    true));
            rules.add(createRule(
                    "reflection-invoke",
                    "(?i)\\.invoke\\s*\\(",
                    "high",
                    true));
                    
            // 文件操作相关
            rules.add(createRule(
                    "file-operation",
                    "(?i)\\b(file_get_contents|fopen|fwrite|fread|readfile)\\s*\\(",
                    "high",
                    true));
                    
            // SSRF相关
            rules.add(createRule(
                    "ssrf-url-connection",
                    "(?i)URLConnection|HttpClient",
                    "medium",
                    true));
            rules.add(createRule(
                    "ssrf-curl",
                    "(?i)\\b(curl|wget)\\s+",
                    "high",
                    true));
            rules.add(createRule(
                    "ssrf-file-protocol",
                    "(?i)file://|[\\\\./]*(etc|windows|winnt)[\\\\./]+passwd",
                    "high",
                    true));
                    
            // 命令注入规则
            rules.add(createRule(
                    "command-injection-pipe",
                    "(?i)[|&;`\\n\\r\\t]",
                    "high",
                    true));
            rules.add(createRule(
                    "command-injection-shell-keywords",
                    "(?i)\\b(cd|dir|ls|cat|cp|mv|rm|ps|kill|ifconfig|ipconfig)\\b",
                    "medium",
                    true));
                    
            // 路径遍历规则
            rules.add(createRule(
                    "path-traversal",
                    "(?i)(\\.\\.[/\\\\])|(\\.\\.[/\\\\])|(\\.\\.[/\\\\])",
                    "high",
                    true));
            rules.add(createRule(
                    "path-traversal-encoded",
                    "(?i)(%2e|%2e%2e|%c0%ae|%uff0e|%uff0e%uff0e)",
                    "high",
                    true));
                    
            // LDAP注入规则
            rules.add(createRule(
                    "ldap-injection",
                    "(?i)[\\n\\r\\t]*\\*.*[\\n\\r\\t]*\\)|[\\n\\r\\t]*\\(|[\\n\\r\\t]+or[\\n\\r\\t]+|[\\n\\r\\t]+and[\\n\\r\\t]+",
                    "medium",
                    true));
                    
            // XXE注入规则
            rules.add(createRule(
                    "xxe-entity",
                    "(?i)<!entity\\s",
                    "high",
                    true));
            rules.add(createRule(
                    "xxe-doctype",
                    "(?i)<!doctype\\s",
                    "medium",
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