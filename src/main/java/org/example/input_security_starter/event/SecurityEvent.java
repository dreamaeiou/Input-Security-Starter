package org.example.input_security_starter.event;

import java.text.SimpleDateFormat;
import java.util.Date;

public class SecurityEvent {
    private final String ruleName;
    private final String inputSnippet;
    private final String url;
    private final String method;
    private String ipAddress;
    private final Date timestamp;

    public SecurityEvent(String ruleName, String inputSnippet, String url, String method) {
        this.ruleName = ruleName;
        this.inputSnippet = inputSnippet;
        this.url = url;
        this.method = method;
        this.timestamp = new Date();
    }
    
    public SecurityEvent(String ruleName, String inputSnippet, String url, String method, String ipAddress) {
        this(ruleName, inputSnippet, url, method);
        this.ipAddress = ipAddress;
    }

    public String getRuleName() { return ruleName; }
    public String getInputSnippet() { return inputSnippet; }
    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public String getIpAddress() { return ipAddress; }
    public Date getTimestamp() { return timestamp; }

    
    // 获取格式化的时间戳字符串
    public String getFormattedTimestamp() {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return formatter.format(timestamp);
    }
    
    // setters...
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

}