package org.example.input_security_starter.event;

import java.time.LocalDateTime;

public class SecurityEvent {
    private final String ruleName;
    private final String inputSnippet;
    private final String url;
    private final String method;
    private String ipAddress;
    private final LocalDateTime timestamp;

    // 构造、getter 省略（可按需补充）
    public SecurityEvent(String ruleName, String inputSnippet, String url, String method) {
        this.ruleName = ruleName;
        this.inputSnippet = inputSnippet;
        this.url = url;
        this.method = method;
        this.timestamp = LocalDateTime.now();
    }
    
    public SecurityEvent(String ruleName, String inputSnippet, String url, String method, String ipAddress) {
        this(ruleName, inputSnippet, url, method);
        this.ipAddress = ipAddress;
    }

    // getters...
    public String getRuleName() { return ruleName; }
    public String getInputSnippet() { return inputSnippet; }
    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public String getIpAddress() { return ipAddress; }
    public LocalDateTime getTimestamp() { return timestamp; }
    
    // setters...
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

}