package org.example.input_security_starter.engine;


import org.example.input_security_starter.model.SecurityRule;
//import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

// 不再使用@Component注解，改由自动配置类来创建Bean
public class RuleEngine {

    private final List<Pattern> compiledPatterns = new ArrayList<>();
    private final List<String> ruleNames = new ArrayList<>();
    
    public RuleEngine() {
    }

    public void loadRules(List<SecurityRule> rules) {
        compiledPatterns.clear();
        ruleNames.clear();

        if (rules == null || rules.isEmpty()) {
            return;
        }

        for (SecurityRule rule : rules) {
            if (rule.isEnabled()) {
                try {
                    int flags = Pattern.CASE_INSENSITIVE;
                    // 对于特定的攻击模式，设置DOTALL标志来匹配换行符
                    if (rule.getName().equals("xss-on-event") || 
                        rule.getName().equals("xss-svg-script") ||
                        rule.getName().equals("xss-script-tag")) {
                        flags |= Pattern.DOTALL;
                    }
                    
                    compiledPatterns.add(Pattern.compile(rule.getPattern(), flags));
                    ruleNames.add(rule.getName());
                } catch (Exception e) {
                    // 静默处理编译错误
                }
            } else {
                // 跳过禁用的规则
            }
        }
    }


    public String match(String input) {
        if (input == null) return null;

        for (int i = 0; i < compiledPatterns.size(); i++) {
            Pattern pattern = compiledPatterns.get(i);
            String ruleName = ruleNames.get(i);

            if (pattern.matcher(input).find()) {
                return ruleName;
            }
        }
        return null;
    }

    // 添加一个方法来获取当前加载的规则数量，用于调试
    public int getLoadedRulesCount() {
        return compiledPatterns.size();
    }

    public List<String> getRuleNames() {
        return new ArrayList<>(ruleNames);
    }

}