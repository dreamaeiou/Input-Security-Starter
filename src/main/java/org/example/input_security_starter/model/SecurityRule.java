package org.example.input_security_starter.model;

public class SecurityRule {
    private String name;
    private String pattern;
    private String level = "high"; // low, medium, high
    private boolean enabled = true;

    // Getters & Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getPattern() { return pattern; }
    public void setPattern(String pattern) { this.pattern = pattern; }
    public String getLevel() { return level; }
    public void setLevel(String level) { this.level = level; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}