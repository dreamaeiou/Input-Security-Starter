package org.example.input_security_starter.event;

import java.time.LocalDateTime;

public class SecurityEvent {
    private String ruleName;
    private String inputSnippet;
    private String url;
    private String method;
    private LocalDateTime timestamp;

    // 构造、getter 省略（可按需补充）
    public SecurityEvent(String ruleName, String inputSnippet, String url, String method) {
        this.ruleName = ruleName;
        this.inputSnippet = inputSnippet;
        this.url = url;
        this.method = method;
        this.timestamp = LocalDateTime.now();
    }

    // getters...
    public String getRuleName() { return ruleName; }
    public String getInputSnippet() { return inputSnippet; }
    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public LocalDateTime getTimestamp() { return timestamp; }
}