package org.example.input_security_starter.engine;

import org.example.input_security_starter.model.SecurityRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 优化规则引擎
 * 基于正则表达式的安全规则匹配引擎，支持：
 * 1. 按优先级分级匹配（high/medium/low）
 * 2. 自动输入规范化后二次匹配
 * 3. 详细的匹配结果返回
 * 
 * 匹配流程：
 * 原始输入 -> 高优先级规则匹配 -> 中优先级规则匹配 -> 低优先级规则匹配
 *      ↓ (未匹配)
 * 输入规范化 -> 再次按优先级匹配
 */
public class OptimizedRuleEngine {
    
    private static final Logger log = LoggerFactory.getLogger(OptimizedRuleEngine.class);
    
    /** 高优先级规则列表（高危攻击：XSS、SQL注入等） */
    private final List<CompiledRule> highPriorityRules = new ArrayList<>();
    /** 中优先级规则列表（中危攻击：SSRF等） */
    private final List<CompiledRule> mediumPriorityRules = new ArrayList<>();
    /** 低优先级规则列表（低危攻击：信息泄露等） */
    private final List<CompiledRule> lowPriorityRules = new ArrayList<>();
    
    /** 已加载规则总数 */
    private int totalRules = 0;
    
    public OptimizedRuleEngine() {
    }
    
    /**
     * 加载安全规则
     * 将规则按优先级分类存储，编译正则表达式以提高匹配效率
     * @param rules 安全规则列表
     */
    public void loadRules(List<SecurityRule> rules) {
        highPriorityRules.clear();
        mediumPriorityRules.clear();
        lowPriorityRules.clear();
        totalRules = 0;

        if (rules == null || rules.isEmpty()) {
            return;
        }

        for (SecurityRule rule : rules) {
            if (rule.isEnabled()) {
                try {
                    // 默认使用大小写不敏感模式
                    int flags = Pattern.CASE_INSENSITIVE;
                    // XSS 相关规则需要 DOTALL 模式以匹配跨行内容
                    if (rule.getName().equals("xss-on-event") || 
                        rule.getName().equals("xss-svg-script") ||
                        rule.getName().equals("xss-script-tag")) {
                        flags |= Pattern.DOTALL;
                    }
                    
                    CompiledRule compiledRule = new CompiledRule(
                        rule.getName(),
                        Pattern.compile(rule.getPattern(), flags),
                        rule.getLevel()
                    );
                    
                    // 按优先级分类存储
                    if ("high".equalsIgnoreCase(rule.getLevel())) {
                        highPriorityRules.add(compiledRule);
                    } else if ("medium".equalsIgnoreCase(rule.getLevel())) {
                        mediumPriorityRules.add(compiledRule);
                    } else {
                        lowPriorityRules.add(compiledRule);
                    }
                    totalRules++;
                    
                } catch (Exception e) {
                    log.error("Failed to compile rule: {}, pattern: {}, error: {}", 
                              rule.getName(), rule.getPattern(), e.getMessage());
                }
            }
        }
    }

    /**
     * 匹配输入是否触发安全规则
     * @param input 待检测的输入字符串
     * @return 触发的规则名称，未匹配则返回 null
     */
    public String match(String input) {
        MatchResult result = matchDetailed(input);
        return result != null ? result.getRuleName() : null;
    }
    
    /**
     * 详细匹配输入是否触发安全规则
     * 匹配流程：
     * 1. 先对原始输入进行规则匹配
     * 2. 如果未匹配，对输入进行规范化后再次匹配
     * 
     * @param input 待检测的输入字符串
     * @return 匹配结果详情，未匹配则返回 null
     */
    public MatchResult matchDetailed(String input) {
        if (input == null) return null;

        // 首先对原始输入进行匹配
        MatchResult result = matchWithPriorityDetailed(input);
        if (result != null) {
            return result;
        }
        
        // 对输入进行规范化处理（解码各种编码）
        String normalizedInput = InputNormalizer.normalize(input);
        
        // 如果规范化后内容有变化，再次匹配
        if (!normalizedInput.equals(input)) {
            result = matchWithPriorityDetailed(normalizedInput);
            if (result != null) {
                return result;
            }
        }
        
        return null;
    }
    
    /**
     * 按优先级顺序匹配规则
     * 匹配顺序：high -> medium -> low
     * @param input 待检测的输入字符串
     * @return 匹配结果详情，未匹配则返回 null
     */
    private MatchResult matchWithPriorityDetailed(String input) {
        if (input == null) return null;
        
        // 高优先级规则匹配
        for (CompiledRule rule : highPriorityRules) {
            java.util.regex.Matcher matcher = rule.pattern.matcher(input);
            if (matcher.find()) {
                return new MatchResult(
                    rule.name,
                    rule.level,
                    matcher.start(),
                    matcher.end() - matcher.start(),
                    matcher.group()
                );
            }
        }
        
        // 中优先级规则匹配
        for (CompiledRule rule : mediumPriorityRules) {
            java.util.regex.Matcher matcher = rule.pattern.matcher(input);
            if (matcher.find()) {
                return new MatchResult(
                    rule.name,
                    rule.level,
                    matcher.start(),
                    matcher.end() - matcher.start(),
                    matcher.group()
                );
            }
        }
        
        // 低优先级规则匹配
        for (CompiledRule rule : lowPriorityRules) {
            java.util.regex.Matcher matcher = rule.pattern.matcher(input);
            if (matcher.find()) {
                return new MatchResult(
                    rule.name,
                    rule.level,
                    matcher.start(),
                    matcher.end() - matcher.start(),
                    matcher.group()
                );
            }
        }
        
        return null;
    }
    
    /**
     * 获取已加载规则总数
     * @return 规则总数
     */
    public int getTotalRules() {
        return totalRules;
    }
    
    /**
     * 获取高优先级规则数量
     * @return 高优先级规则数量
     */
    public int getHighPriorityRuleCount() {
        return highPriorityRules.size();
    }
    
    /**
     * 获取中优先级规则数量
     * @return 中优先级规则数量
     */
    public int getMediumPriorityRuleCount() {
        return mediumPriorityRules.size();
    }
    
    /**
     * 获取低优先级规则数量
     * @return 低优先级规则数量
     */
    public int getLowPriorityRuleCount() {
        return lowPriorityRules.size();
    }
    
    /**
     * 编译后的规则内部类
     * 存储规则名称、编译后的正则表达式和优先级
     */
    private static class CompiledRule {
        /** 规则名称 */
        final String name;
        /** 编译后的正则表达式 */
        final Pattern pattern;
        /** 规则优先级（high/medium/low） */
        final String level;
        
        CompiledRule(String name, Pattern pattern, String level) {
            this.name = name;
            this.pattern = pattern;
            this.level = level;
        }
    }
    
    /**
     * 匹配结果详情类
     * 包含匹配的规则信息、位置和匹配内容
     */
    public static class MatchResult {
        /** 触发的规则名称 */
        private final String ruleName;
        /** 规则优先级 */
        private final String level;
        /** 匹配起始位置 */
        private final int position;
        /** 匹配内容长度 */
        private final int length;
        /** 匹配到的具体内容 */
        private final String matchedPattern;
        
        public MatchResult(String ruleName, String level, int position, int length, String matchedPattern) {
            this.ruleName = ruleName;
            this.level = level;
            this.position = position;
            this.length = length;
            this.matchedPattern = matchedPattern;
        }
        
        public String getRuleName() { return ruleName; }
        public String getLevel() { return level; }
        public int getPosition() { return position; }
        public int getLength() { return length; }
        public String getMatchedPattern() { return matchedPattern; }
    }
}
