package org.example.input_security_starter.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.config.InputSecurityProperties;
import org.example.input_security_starter.engine.OptimizedRuleEngine;
import org.example.input_security_starter.event.EventRecorder;
import org.example.input_security_starter.filter.InputSecurityFilter;
import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.llm.analysis.LlmAnalysisService;
import org.example.input_security_starter.llm.ip.AbuseIpDbClient;
import org.example.input_security_starter.llm.ip.IpQueryService;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.llm.provider.aliyun.AliyunBailianConfig;
import org.example.input_security_starter.llm.provider.aliyun.AliyunBailianProvider;
import org.example.input_security_starter.llm.provider.glm.GlmConfig;
import org.example.input_security_starter.llm.provider.glm.GlmProvider;
import org.example.input_security_starter.llm.schedule.AlertCounter;
import org.example.input_security_starter.llm.schedule.ScheduledAnalysisTask;
import org.example.input_security_starter.notification.feishu.FeishuClient;
import org.example.input_security_starter.notification.feishu.FeishuNotifier;
import org.example.input_security_starter.notification.wecom.WeComClient;
import org.example.input_security_starter.notification.wecom.WeComNotifier;
import org.example.input_security_starter.notification.dingtalk.DingTalkClient;
import org.example.input_security_starter.notification.dingtalk.DingTalkNotifier;
import org.example.input_security_starter.tracker.AttackerIndex;
import org.example.input_security_starter.tracker.AttackChainAlert;
import org.example.input_security_starter.tracker.AttackChainTracker;
import org.example.input_security_starter.web.InputSecurityController;
import org.example.input_security_starter.web.ViewController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

@Configuration
@EnableConfigurationProperties(InputSecurityProperties.class)
@EnableScheduling
@ConditionalOnProperty(prefix = "input-security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class InputSecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(InputSecurityAutoConfiguration.class);

    @Bean
    public OptimizedRuleEngine ruleEngine(InputSecurityProperties properties) {
        OptimizedRuleEngine engine = new OptimizedRuleEngine();
        engine.loadRules(properties.getRules());
        return engine;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.attack-chain", name = {"enabled", "attacker-index-enabled"}, havingValue = "true", matchIfMissing = true)
    public AttackerIndex attackerIndex(InputSecurityProperties properties) {
        InputSecurityProperties.AttackChainConfig config = properties.getAttackChain();
        AttackerIndex index = new AttackerIndex(
            config.getMaxProfiles(),
            config.getProfileTtlDays(),
            config.getEvictionBatchSize(),
            config.getStatsUpdateInterval(),
            config.getMaxRecentSessions(),
            config.getRelatedTimeWindowMinutes()
        );
        log.info("AttackerIndex created: maxProfiles={}, ttlDays={}, evictionBatch={}, statsInterval={}",
            config.getMaxProfiles(), config.getProfileTtlDays(), config.getEvictionBatchSize(), config.getStatsUpdateInterval());
        return index;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.attack-chain", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AttackChainTracker attackChainTracker(
            InputSecurityProperties properties,
            @org.springframework.beans.factory.annotation.Autowired(required = false) AlertCounter alertCounter,
            @org.springframework.beans.factory.annotation.Autowired(required = false) AttackerIndex attackerIndex) {
        InputSecurityProperties.AttackChainConfig config = properties.getAttackChain();
        
        AttackChainTracker tracker = new AttackChainTracker(
            config.getMaxSessions(),
            config.getSessionTimeoutMinutes(),
            config.getMaxEventsPerSession(),
            config.getMinPhasesForChain(),
            config.getRiskScoreThreshold()
        );
        tracker.setEventConfidenceThreshold(config.getEventConfidenceThreshold());
        tracker.setMaxRelatedAttackers(config.getMaxRelatedAttackers());

        if (attackerIndex != null) {
            tracker.setAttackerIndex(attackerIndex);
        }
        
        tracker.setAlertHandler(alert -> handleAlert(alert, config.getAlertLogPath(), alertCounter));
        
        log.info("AttackChainTracker created with config: maxSessions={}, timeout={}min, riskThreshold={}, eventConfidenceThreshold={}, attackerIndexEnabled={}",
                 config.getMaxSessions(), config.getSessionTimeoutMinutes(), config.getRiskScoreThreshold(),
                 config.getEventConfidenceThreshold(),
                 attackerIndex != null);
        
        return tracker;
    }

    @Bean
    @ConditionalOnMissingBean
    public EventRecorder eventRecorder(InputSecurityProperties properties,
                                        @org.springframework.beans.factory.annotation.Autowired(required = false)
                                        AttackChainTracker attackChainTracker) {
        EventRecorder recorder = new EventRecorder(
            properties.getLogFilePath(), 
            properties.getMaxLogSizeMb(), 
            properties.getMaxLogFiles(),
            properties.isAsyncLogEnabled()
        );
        
        if (attackChainTracker != null) {
            recorder.setAttackChainTracker(attackChainTracker);
            log.info("AttackChainTracker injected into EventRecorder");
        }
        
        return recorder;
    }

    @Bean
    public FilterRegistrationBean<InputSecurityFilter> inputSecurityFilter(
            InputSecurityProperties properties,
            OptimizedRuleEngine ruleEngine,
            EventRecorder eventRecorder) {
        FilterRegistrationBean<InputSecurityFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new InputSecurityFilter(properties, ruleEngine, eventRecorder, properties.getTrustedProxies()));
        registration.addUrlPatterns("/*");
        registration.setOrder(properties.getFilterOrder());
        registration.setName("inputSecurityFilter");
        
        return registration;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security", name = "enable-ui", havingValue = "true")
    public InputSecurityController inputSecurityController(
            OptimizedRuleEngine ruleEngine,
            EventRecorder eventRecorder,
            @org.springframework.beans.factory.annotation.Autowired(required = false) LlmAnalysisService llmAnalysisService,
            @org.springframework.beans.factory.annotation.Autowired(required = false) ScheduledAnalysisTask scheduledAnalysisTask,
            @org.springframework.beans.factory.annotation.Autowired(required = false) AlertCounter alertCounter,
            @org.springframework.beans.factory.annotation.Autowired(required = false) FeishuNotifier feishuNotifier,
            @org.springframework.beans.factory.annotation.Autowired(required = false) WeComNotifier weComNotifier,
            @org.springframework.beans.factory.annotation.Autowired(required = false) DingTalkNotifier dingTalkNotifier) {
        log.info("Creating InputSecurityController (enable-ui=true)");
        return new InputSecurityController(ruleEngine, eventRecorder, llmAnalysisService, scheduledAnalysisTask, alertCounter, feishuNotifier, weComNotifier, dingTalkNotifier);
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security", name = "enable-ui", havingValue = "true")
    public ViewController viewController(OptimizedRuleEngine ruleEngine, EventRecorder eventRecorder, InputSecurityProperties properties) {
        log.info("Creating ViewController (enable-ui=true)");
        return new ViewController(ruleEngine, eventRecorder, properties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm", name = "enabled", havingValue = "true")
    public LlmProvider llmProvider(InputSecurityProperties properties) {
        String provider = properties.getLlm().getProvider();
        InputSecurityProperties.AdvancedConfig advanced = properties.getLlm().getAdvanced();
        
        if ("glm".equalsIgnoreCase(provider)) {
            InputSecurityProperties.GlmProviderConfig glmConfig = properties.getLlm().getGlm();
            GlmConfig config = new GlmConfig(glmConfig.getApiUrl(), glmConfig.getApiKey(), glmConfig.getModel());
            applyAdvancedConfig(config, glmConfig, advanced);
            GlmProvider glmProvider = new GlmProvider(config);
            log.info("GlmProvider created with model: {}", glmConfig.getModel());
            return glmProvider;
        } else if ("aliyun-bailian".equalsIgnoreCase(provider)) {
            InputSecurityProperties.AliyunBailianProviderConfig aliyunConfig = properties.getLlm().getAliyunBailian();
            AliyunBailianConfig config = new AliyunBailianConfig(
                aliyunConfig.getApiUrl(), 
                aliyunConfig.getApiKey(), 
                aliyunConfig.getModel()
            );
            applyAdvancedConfig(config, aliyunConfig, advanced);
            AliyunBailianProvider aliyunProvider = new AliyunBailianProvider(config);
            log.info("AliyunBailianProvider created with model: {}", aliyunConfig.getModel());
            return aliyunProvider;
        }
        throw new IllegalArgumentException("Unsupported LLM provider: " + provider);
    }
    
    private void applyAdvancedConfig(Object targetConfig, Object providerConfig, InputSecurityProperties.AdvancedConfig advanced) {
        int connectTimeoutMs = advanced.getConnectTimeoutMs();
        int readTimeoutMs = advanced.getReadTimeoutMs();
        int maxRetries = advanced.getMaxRetries();
        long retryBaseDelayMs = advanced.getRetryBaseDelayMs();
        long retryMaxDelayMs = advanced.getRetryMaxDelayMs();
        int circuitFailureThreshold = advanced.getCircuitFailureThreshold();
        long circuitOpenWindowMs = advanced.getCircuitOpenWindowMs();
        int requestsPerMinute = advanced.getRequestsPerMinute();
        
        if (targetConfig instanceof GlmConfig) {
            GlmConfig config = (GlmConfig) targetConfig;
            config.setConnectTimeoutMs(connectTimeoutMs);
            config.setReadTimeoutMs(readTimeoutMs);
            config.setMaxRetries(maxRetries);
            config.setRetryBaseDelayMs(retryBaseDelayMs);
            config.setRetryMaxDelayMs(retryMaxDelayMs);
            config.setCircuitFailureThreshold(circuitFailureThreshold);
            config.setCircuitOpenWindowMs(circuitOpenWindowMs);
            config.setMaxRequestsPerMinute(requestsPerMinute);
        } else if (targetConfig instanceof AliyunBailianConfig) {
            AliyunBailianConfig config = (AliyunBailianConfig) targetConfig;
            config.setConnectTimeoutMs(connectTimeoutMs);
            config.setReadTimeoutMs(readTimeoutMs);
            config.setMaxRetries(maxRetries);
            config.setRetryBaseDelayMs(retryBaseDelayMs);
            config.setRetryMaxDelayMs(retryMaxDelayMs);
            config.setCircuitFailureThreshold(circuitFailureThreshold);
            config.setCircuitOpenWindowMs(circuitOpenWindowMs);
            config.setMaxRequestsPerMinute(requestsPerMinute);
        }
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm", name = "enabled", havingValue = "true")
    public AbuseIpDbClient abuseIpDbClient(InputSecurityProperties properties) {
        InputSecurityProperties.LlmConfig config = properties.getLlm();
        AbuseIpDbClient client = new AbuseIpDbClient(
            config.getAbuseIpDbApiUrl(), 
            config.getAbuseIpDbApiKey(), 
            config.getAbuseIpDbMaxAgeDays()
        );
        log.info("AbuseIpDbClient created with maxAgeDays: {}", config.getAbuseIpDbMaxAgeDays());
        return client;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm", name = "enabled", havingValue = "true")
    public IpQueryService ipQueryService(AbuseIpDbClient abuseIpDbClient, InputSecurityProperties properties) {
        String ipLogDir = properties.getLlm().getIpLogDir();
        IpQueryService service = new IpQueryService(abuseIpDbClient, ipLogDir);
        log.info("IpQueryService created with logDir: {}", ipLogDir);
        return service;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm", name = "enabled", havingValue = "true")
    public LlmAnalysisService llmAnalysisService(
            LlmProvider llmProvider, 
            AbuseIpDbClient abuseIpDbClient,
            IpQueryService ipQueryService,
            InputSecurityProperties properties,
            @org.springframework.beans.factory.annotation.Autowired(required = false) FeishuNotifier feishuNotifier,
            @org.springframework.beans.factory.annotation.Autowired(required = false) WeComNotifier weComNotifier,
            @org.springframework.beans.factory.annotation.Autowired(required = false) DingTalkNotifier dingTalkNotifier) {
        String alertLogPath = properties.getAttackChain().getAlertLogPath();
        InputSecurityProperties.LlmConfig llmConfig = properties.getLlm();
        LlmAnalysisService service = new LlmAnalysisService(
            llmProvider,
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            llmConfig.getMaxAlertsPerAnalysis(),
            llmConfig.getMaxPromptChars(),
            llmConfig.getMaxIpsPerAnalysis(),
            llmConfig.getMaxEventsPerIp(),
            llmConfig.getAnalysisTimeoutMs(),
            feishuNotifier,
            weComNotifier,
            dingTalkNotifier
        );
        log.info("LlmAnalysisService created with provider: {}, monitoring alert log: {}", llmProvider.getName(), alertLogPath);
        return service;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.feishu", name = "enabled", havingValue = "true")
    public FeishuClient feishuClient(InputSecurityProperties properties) {
        InputSecurityProperties.FeishuConfig config = properties.getLlm().getFeishu();
        FeishuClient client = new FeishuClient(
            config.getWebhookUrl(),
            config.getAppId(),
            config.getAppSecret(),
            config.getReceiveIdType(),
            config.getReceiveId(),
            config.isEnabled()
        );
        log.info("FeishuClient created: enabled={}, useAppApi={}", config.isEnabled(), client.isUseAppApi());
        return client;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.feishu", name = "enabled", havingValue = "true")
    public FeishuNotifier feishuNotifier(FeishuClient feishuClient) {
        FeishuNotifier notifier = new FeishuNotifier(feishuClient);
        log.info("FeishuNotifier created");
        return notifier;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.wecom", name = "enabled", havingValue = "true")
    public WeComClient weComClient(InputSecurityProperties properties) {
        InputSecurityProperties.WeComConfig config = properties.getLlm().getWecom();
        WeComClient client = new WeComClient(
            config.getWebhookUrl(),
            config.getCorpId(),
            config.getCorpSecret(),
            config.getAgentId(),
            config.getToUser(),
            config.getToParty(),
            config.getToTag(),
            config.isEnabled()
        );
        log.info("WeComClient created: enabled={}, useAppApi={}", config.isEnabled(), client.isUseAppApi());
        return client;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.wecom", name = "enabled", havingValue = "true")
    public WeComNotifier weComNotifier(WeComClient weComClient) {
        WeComNotifier notifier = new WeComNotifier(weComClient);
        log.info("WeComNotifier created");
        return notifier;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.dingtalk", name = "enabled", havingValue = "true")
    public DingTalkClient dingTalkClient(InputSecurityProperties properties) {
        InputSecurityProperties.DingTalkConfig config = properties.getLlm().getDingtalk();
        DingTalkClient client = new DingTalkClient(
            config.getWebhookUrl(),
            config.getAppKey(),
            config.getAppSecret(),
            config.getAgentId(),
            config.getUseridList(),
            config.getDeptIdList(),
            config.isToAllUser(),
            config.isEnabled()
        );
        log.info("DingTalkClient created: enabled={}, useAppApi={}", config.isEnabled(), client.isUseAppApi());
        return client;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.dingtalk", name = "enabled", havingValue = "true")
    public DingTalkNotifier dingTalkNotifier(DingTalkClient dingTalkClient) {
        DingTalkNotifier notifier = new DingTalkNotifier(dingTalkClient);
        log.info("DingTalkNotifier created");
        return notifier;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.auto-analysis", name = "enabled", havingValue = "true")
    public AlertCounter alertCounter(InputSecurityProperties properties) {
        String alertLogPath = properties.getAttackChain().getAlertLogPath();
        int alertThreshold = properties.getLlm().getAutoAnalysis().getAlertThreshold();
        AlertCounter counter = new AlertCounter(alertLogPath, alertThreshold);
        log.info("AlertCounter created with threshold: {}", alertThreshold);
        return counter;
    }

    @Bean
    @ConditionalOnProperty(prefix = "input-security.llm.auto-analysis", name = "enabled", havingValue = "true")
    public ScheduledAnalysisTask scheduledAnalysisTask(
            LlmAnalysisService llmAnalysisService,
            AlertCounter alertCounter,
            InputSecurityProperties properties,
            @org.springframework.beans.factory.annotation.Autowired(required = false) FeishuNotifier feishuNotifier,
            @org.springframework.beans.factory.annotation.Autowired(required = false) WeComNotifier weComNotifier,
            @org.springframework.beans.factory.annotation.Autowired(required = false) DingTalkNotifier dingTalkNotifier) {
        
        InputSecurityProperties.AutoAnalysisConfig config = properties.getLlm().getAutoAnalysis();
        
        ScheduledAnalysisTask task = new ScheduledAnalysisTask(
            llmAnalysisService,
            alertCounter,
            config.isEnabled(),
            config.getScheduleIntervalMs(),
            config.getScheduleCron(),
            feishuNotifier,
            weComNotifier,
            dingTalkNotifier
        );
        
        log.info("ScheduledAnalysisTask created: enabled={}, threshold={}, intervalHours={}, cron={}, countCheckIntervalMs={}",
                config.isEnabled(), 
                config.getAlertThreshold(),
                config.getScheduleIntervalHours(),
                config.getScheduleCron(),
                config.getCountCheckIntervalMs());
        
        return task;
    }
    
    private void handleAlert(AttackChainAlert alert, String logPath, AlertCounter alertCounter) {
        try {
            String validatedPath = validateLogFilePath(logPath);
            String json = new ObjectMapper().writeValueAsString(alert.toMap());
            
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(validatedPath, true))) {
                writer.write(json);
                writer.newLine();
            }
            
            log.warn("Attack chain alert: type={}, session={}, ip={}, phases={}",
                     alert.getAlertType(), alert.getSessionId(), alert.getClientIp(),
                     alert.getTriggeredPhases());
            
            if (alertCounter != null) {
                alertCounter.onNewAlert();
            }
                     
        } catch (IOException e) {
            log.error("Failed to write attack chain alert: {}", e.getMessage());
        } catch (SecurityException e) {
            log.error("Security violation in alert log path: {}", e.getMessage());
        }
    }
    
    private String validateLogFilePath(String path) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("Log file path cannot be null or empty");
        }
        
        String normalizedPath = path.trim();
        
        if (normalizedPath.contains("..")) {
            throw new SecurityException("Path traversal detected in log file path: " + path);
        }
        
        if (normalizedPath.startsWith("/") || normalizedPath.startsWith("\\") ||
            (normalizedPath.length() > 1 && normalizedPath.charAt(1) == ':')) {
            String[] dangerousPaths = {
                "/etc/", "/root/", "/home/", "/var/log/",
                "C:\\Windows\\", "C:\\Program Files\\", "C:\\Users\\",
                "/proc/", "/sys/", "/dev/"
            };
            
            for (String dangerous : dangerousPaths) {
                if (normalizedPath.toLowerCase().startsWith(dangerous.toLowerCase())) {
                    throw new SecurityException("Cannot write log to system directory: " + path);
                }
            }
        }
        
        String fileName = new File(normalizedPath).getName();
        if (!fileName.endsWith(".log") && !fileName.endsWith(".json")) {
            log.warn("Log file path does not have standard extension (.log/.json): {}", path);
        }
        
        return normalizedPath;
    }
}
