package org.example.input_security_starter.model;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 安全规则实体类
 * 定义单个安全检测规则的属性，包括：
 * 1. 规则名称 - 唯一标识
 * 2. 正则表达式模式 - 用于匹配恶意输入
 * 3. 规则级别 - high/medium/low
 * 4. 启用状态 - 是否生效
 * 
 * 支持正则表达式验证和级别校验
 */
public class SecurityRule {
    
    /** 有效的规则级别集合 */
    private static final Set<String> VALID_LEVELS = new HashSet<>(Arrays.asList("low", "medium", "high"));
    
    /** 规则名称 */
    private String name;
    /** 正则表达式模式 */
    private String pattern;
    /** 规则级别，默认为 high */
    private String level = "high";
    /** 是否启用，默认为 true */
    private boolean enabled = true;

    /**
     * 获取规则名称
     * @return 规则名称
     */
    public String getName() { return name; }
    
    /**
     * 设置规则名称
     * @param name 规则名称
     */
    public void setName(String name) { this.name = name; }
    
    /**
     * 获取正则表达式模式
     * @return 正则表达式模式字符串
     */
    public String getPattern() { return pattern; }
    
    /**
     * 设置正则表达式模式
     * 设置时会验证正则表达式语法是否有效
     * @param pattern 正则表达式模式字符串
     * @throws IllegalArgumentException 如果正则表达式语法无效
     */
    public void setPattern(String pattern) { 
        if (pattern != null && !pattern.isEmpty()) {
            try {
                Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException("Invalid regex pattern: " + e.getMessage());
            }
        }
        this.pattern = pattern; 
    }
    
    /**
     * 获取规则级别
     * @return 规则级别（high/medium/low）
     */
    public String getLevel() { return level; }
    
    /**
     * 设置规则级别
     * @param level 规则级别，必须是 low/medium/high 之一
     * @throws IllegalArgumentException 如果级别无效
     */
    public void setLevel(String level) { 
        if (level != null && !VALID_LEVELS.contains(level.toLowerCase())) {
            throw new IllegalArgumentException("Invalid level: " + level + ". Must be one of: " + VALID_LEVELS);
        }
        this.level = level != null ? level.toLowerCase() : "high"; 
    }
    
    /**
     * 检查规则是否启用
     * @return 是否启用
     */
    public boolean isEnabled() { return enabled; }
    
    /**
     * 设置规则启用状态
     * @param enabled 是否启用
     */
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    
    /**
     * 验证规则是否有效
     * 规则必须具有非空名称、非空模式和有效级别
     * @return 规则是否有效
     */
    public boolean isValid() {
        return name != null && !name.isEmpty() 
            && pattern != null && !pattern.isEmpty()
            && VALID_LEVELS.contains(level.toLowerCase());
    }
}
