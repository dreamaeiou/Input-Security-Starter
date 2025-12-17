package org.example.input_security_starter.autoconfigure;


import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.RuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.filiter.InputSecurityFilter;
import org.example.input_security_starter.web.InputSecurityController;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(InputSecurityProperties.class)
@ConditionalOnProperty(prefix = "input-security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class InputSecurityAutoConfiguration {

    public InputSecurityAutoConfiguration() {
    }

    // 规则引擎
    @Bean
    public RuleEngine ruleEngine(InputSecurityProperties properties) {
        RuleEngine engine = new RuleEngine();
        engine.loadRules(properties.getRules());
        return engine;
    }

    // 事件记录器
    @Bean
    @ConditionalOnMissingBean
    public EventRecorder eventRecorder() {
        return new EventRecorder();
    }

    // 过滤器
    @Bean
    public FilterRegistrationBean<InputSecurityFilter> inputSecurityFilter(
            InputSecurityProperties properties,
            RuleEngine ruleEngine,
            EventRecorder eventRecorder) {
        FilterRegistrationBean<InputSecurityFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new InputSecurityFilter(properties, ruleEngine, eventRecorder));
        registration.addUrlPatterns("/*");
        registration.setOrder(-100); // 高优先级
        return registration;
    }

    // 注意：移除了inputSecurityController的@Bean定义，因为InputSecurityController类本身有@RestController注解，
    // 会被组件扫描自动注册为Bean，避免重复定义
}