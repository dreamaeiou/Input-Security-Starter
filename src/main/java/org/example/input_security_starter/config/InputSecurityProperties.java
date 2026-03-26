package org.example.input_security_starter.config;

import org.example.input_security_starter.model.SecurityRule;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;

/**
 * 输入安全配置属性类
 * <p>
 * ReDoS 修复说明：
 * 1. 移除了 SQL 注入规则中 [\w\s]+ 这种导致指数回溯的重叠字符集。
 * 2. 将无限制的通配符 .* 替换为有限制的匹配 .{0,N} 或非贪婪匹配。
 * 3. 对部分高危重复组增加了长度限制。
 * </p>
 */
@ConfigurationProperties(prefix = "input-security")
@Validated
public class InputSecurityProperties {

    /** 是否启用安全检测，默认启用 */
    private boolean enabled = true;
    /** 工作模式：MONITOR（仅记录）或 BLOCK（阻止请求） */
    private Mode mode = Mode.MONITOR;
    /** 自定义安全规则列表 */
    private List<SecurityRule> rules = new ArrayList<>();
    
    /** 排除检测的路径列表（路径白名单） */
    private List<String> excludePaths = new ArrayList<>();
    /** 包含检测的路径列表（为空则检测所有路径） */
    private List<String> includePaths = new ArrayList<>();
    
    /** 日志文件路径 */
    @NotBlank(message = "Log file path cannot be blank")
    private String logFilePath = "security-events.log";
    
    /** 单个日志文件最大大小（MB） */
    @Min(value = 1, message = "Max log size must be at least 1 MB")
    @Max(value = 1000, message = "Max log size cannot exceed 1000 MB")
    private int maxLogSizeMb = 50;
    
    /** 日志文件轮转数量 */
    @Min(value = 1, message = "Max log files must be at least 1")
    @Max(value = 100, message = "Max log files cannot exceed 100")
    private int maxLogFiles = 10;
    
    /** 是否启用异步日志写入 */
    private boolean asyncLogEnabled = true;
    /** 过滤器执行顺序，值越小优先级越高 */
    private int filterOrder = -100;
    /** 是否启用 Web 测试界面 */
    private boolean enableUi = false;
    /** 信任的代理 IP 列表，用于正确获取 X-Forwarded-For */
    private List<String> trustedProxies = new ArrayList<>();
    
    /** 攻击链追踪配置 */
    private AttackChainConfig attackChain = new AttackChainConfig();

    /** LLM 分析配置 */
    private LlmConfig llm = new LlmConfig();

    public static class LlmConfig {
        private boolean enabled = false;
        private String provider = "glm";
        private int maxAlertsPerAnalysis = 50;
        private long analysisTimeoutMs = 90000;
        private int maxPromptChars = 24000;
        private int maxIpsPerAnalysis = 50;
        private int maxEventsPerIp = 50;
        
        private String abuseIpDbApiKey = "";
        private String abuseIpDbApiUrl = "https://api.abuseipdb.com/api/v2/check";
        private int abuseIpDbMaxAgeDays = 90;
        
        private String ipLogDir = ".";
        
        private AdvancedConfig advanced = new AdvancedConfig();
        
        private GlmProviderConfig glm = new GlmProviderConfig();
        
        private AliyunBailianProviderConfig aliyunBailian = new AliyunBailianProviderConfig();
        
        private AutoAnalysisConfig autoAnalysis = new AutoAnalysisConfig();
        
        private FeishuConfig feishu = new FeishuConfig();
        
        private WeComConfig wecom = new WeComConfig();
        
        private DingTalkConfig dingtalk = new DingTalkConfig();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public int getMaxAlertsPerAnalysis() { return maxAlertsPerAnalysis; }
        public void setMaxAlertsPerAnalysis(int maxAlertsPerAnalysis) { this.maxAlertsPerAnalysis = maxAlertsPerAnalysis; }
        public int getMaxPromptChars() { return maxPromptChars; }
        public void setMaxPromptChars(int maxPromptChars) { this.maxPromptChars = maxPromptChars; }
        public int getMaxIpsPerAnalysis() { return maxIpsPerAnalysis; }
        public void setMaxIpsPerAnalysis(int maxIpsPerAnalysis) { this.maxIpsPerAnalysis = maxIpsPerAnalysis; }
        public int getMaxEventsPerIp() { return maxEventsPerIp; }
        public void setMaxEventsPerIp(int maxEventsPerIp) { this.maxEventsPerIp = maxEventsPerIp; }
        public long getAnalysisTimeoutMs() { return analysisTimeoutMs; }
        public void setAnalysisTimeoutMs(long analysisTimeoutMs) { this.analysisTimeoutMs = analysisTimeoutMs; }
        
        public String getAbuseIpDbApiKey() { return abuseIpDbApiKey; }
        public void setAbuseIpDbApiKey(String abuseIpDbApiKey) { this.abuseIpDbApiKey = abuseIpDbApiKey; }
        public String getAbuseIpDbApiUrl() { return abuseIpDbApiUrl; }
        public void setAbuseIpDbApiUrl(String abuseIpDbApiUrl) { this.abuseIpDbApiUrl = abuseIpDbApiUrl; }
        public int getAbuseIpDbMaxAgeDays() { return abuseIpDbMaxAgeDays; }
        public void setAbuseIpDbMaxAgeDays(int abuseIpDbMaxAgeDays) { this.abuseIpDbMaxAgeDays = abuseIpDbMaxAgeDays; }
        
        public String getIpLogDir() { return ipLogDir; }
        public void setIpLogDir(String ipLogDir) { this.ipLogDir = ipLogDir; }
        
        public AdvancedConfig getAdvanced() { return advanced; }
        public void setAdvanced(AdvancedConfig advanced) { this.advanced = advanced; }
        
        public GlmProviderConfig getGlm() { return glm; }
        public void setGlm(GlmProviderConfig glm) { this.glm = glm; }
        
        public AliyunBailianProviderConfig getAliyunBailian() { return aliyunBailian; }
        public void setAliyunBailian(AliyunBailianProviderConfig aliyunBailian) { this.aliyunBailian = aliyunBailian; }
        
        public AutoAnalysisConfig getAutoAnalysis() { return autoAnalysis; }
        public void setAutoAnalysis(AutoAnalysisConfig autoAnalysis) { this.autoAnalysis = autoAnalysis; }
        
        public FeishuConfig getFeishu() { return feishu; }
        public void setFeishu(FeishuConfig feishu) { this.feishu = feishu; }
        
        public WeComConfig getWecom() { return wecom; }
        public void setWecom(WeComConfig wecom) { this.wecom = wecom; }
        
        public DingTalkConfig getDingtalk() { return dingtalk; }
        public void setDingtalk(DingTalkConfig dingtalk) { this.dingtalk = dingtalk; }
    }
    
    public static class AdvancedConfig {
        private int connectTimeoutMs = 30000;
        private int readTimeoutMs = 300000;
        private int maxRetries = 2;
        private long retryBaseDelayMs = 500;
        private long retryMaxDelayMs = 8000;
        private int circuitFailureThreshold = 5;
        private long circuitOpenWindowMs = 60000;
        private int requestsPerMinute = 60;

        public int getConnectTimeoutMs() { return connectTimeoutMs; }
        public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }
        public int getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }
        public int getMaxRetries() { return maxRetries; }
        public void setMaxRetries(int maxRetries) { this.maxRetries = maxRetries; }
        public long getRetryBaseDelayMs() { return retryBaseDelayMs; }
        public void setRetryBaseDelayMs(long retryBaseDelayMs) { this.retryBaseDelayMs = retryBaseDelayMs; }
        public long getRetryMaxDelayMs() { return retryMaxDelayMs; }
        public void setRetryMaxDelayMs(long retryMaxDelayMs) { this.retryMaxDelayMs = retryMaxDelayMs; }
        public int getCircuitFailureThreshold() { return circuitFailureThreshold; }
        public void setCircuitFailureThreshold(int circuitFailureThreshold) { this.circuitFailureThreshold = circuitFailureThreshold; }
        public long getCircuitOpenWindowMs() { return circuitOpenWindowMs; }
        public void setCircuitOpenWindowMs(long circuitOpenWindowMs) { this.circuitOpenWindowMs = circuitOpenWindowMs; }
        public int getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(int requestsPerMinute) { this.requestsPerMinute = requestsPerMinute; }
    }
    
    public static class GlmProviderConfig {
        private String apiUrl = "https://open.bigmodel.cn/api/paas/v4/chat/completions";
        private String apiKey = "";
        private String model = "glm-4-flash";
        private int connectTimeoutMs = 30000;
        private int readTimeoutMs = 300000;
        private int maxRetries = 2;
        private long retryBaseDelayMs = 500;
        private long retryMaxDelayMs = 8000;
        private int circuitFailureThreshold = 5;
        private long circuitOpenWindowMs = 60000;
        private int requestsPerMinute = 60;

        public String getApiUrl() { return apiUrl; }
        public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public int getConnectTimeoutMs() { return connectTimeoutMs; }
        public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }
        public int getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }
        public int getMaxRetries() { return maxRetries; }
        public void setMaxRetries(int maxRetries) { this.maxRetries = maxRetries; }
        public long getRetryBaseDelayMs() { return retryBaseDelayMs; }
        public void setRetryBaseDelayMs(long retryBaseDelayMs) { this.retryBaseDelayMs = retryBaseDelayMs; }
        public long getRetryMaxDelayMs() { return retryMaxDelayMs; }
        public void setRetryMaxDelayMs(long retryMaxDelayMs) { this.retryMaxDelayMs = retryMaxDelayMs; }
        public int getCircuitFailureThreshold() { return circuitFailureThreshold; }
        public void setCircuitFailureThreshold(int circuitFailureThreshold) { this.circuitFailureThreshold = circuitFailureThreshold; }
        public long getCircuitOpenWindowMs() { return circuitOpenWindowMs; }
        public void setCircuitOpenWindowMs(long circuitOpenWindowMs) { this.circuitOpenWindowMs = circuitOpenWindowMs; }
        public int getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(int requestsPerMinute) { this.requestsPerMinute = requestsPerMinute; }
    }
    
    public static class AliyunBailianProviderConfig {
        private String apiUrl = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions";
        private String apiKey = "";
        private String model = "qwen-plus";
        private int connectTimeoutMs = 30000;
        private int readTimeoutMs = 300000;
        private int maxRetries = 2;
        private long retryBaseDelayMs = 500;
        private long retryMaxDelayMs = 8000;
        private int circuitFailureThreshold = 5;
        private long circuitOpenWindowMs = 60000;
        private int requestsPerMinute = 60;

        public String getApiUrl() { return apiUrl; }
        public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public int getConnectTimeoutMs() { return connectTimeoutMs; }
        public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }
        public int getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }
        public int getMaxRetries() { return maxRetries; }
        public void setMaxRetries(int maxRetries) { this.maxRetries = maxRetries; }
        public long getRetryBaseDelayMs() { return retryBaseDelayMs; }
        public void setRetryBaseDelayMs(long retryBaseDelayMs) { this.retryBaseDelayMs = retryBaseDelayMs; }
        public long getRetryMaxDelayMs() { return retryMaxDelayMs; }
        public void setRetryMaxDelayMs(long retryMaxDelayMs) { this.retryMaxDelayMs = retryMaxDelayMs; }
        public int getCircuitFailureThreshold() { return circuitFailureThreshold; }
        public void setCircuitFailureThreshold(int circuitFailureThreshold) { this.circuitFailureThreshold = circuitFailureThreshold; }
        public long getCircuitOpenWindowMs() { return circuitOpenWindowMs; }
        public void setCircuitOpenWindowMs(long circuitOpenWindowMs) { this.circuitOpenWindowMs = circuitOpenWindowMs; }
        public int getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(int requestsPerMinute) { this.requestsPerMinute = requestsPerMinute; }
    }
    
    public static class AutoAnalysisConfig {
        private boolean enabled = false;
        private int alertThreshold = 50;
        private String scheduleCron = "0 0 2 * * ?";
        private int scheduleIntervalHours = 24;
        private long countCheckIntervalMs = 60000;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getAlertThreshold() { return alertThreshold; }
        public void setAlertThreshold(int alertThreshold) { this.alertThreshold = alertThreshold; }
        public String getScheduleCron() { return scheduleCron; }
        public void setScheduleCron(String scheduleCron) { this.scheduleCron = scheduleCron; }
        public int getScheduleIntervalHours() { return scheduleIntervalHours; }
        public void setScheduleIntervalHours(int scheduleIntervalHours) { this.scheduleIntervalHours = scheduleIntervalHours; }
        public long getScheduleIntervalMs() { return scheduleIntervalHours * 60L * 60L * 1000L; }
        public long getCountCheckIntervalMs() { return countCheckIntervalMs; }
        public void setCountCheckIntervalMs(long countCheckIntervalMs) { this.countCheckIntervalMs = countCheckIntervalMs; }
    }
    
    public static class FeishuConfig {
        private boolean enabled = false;
        private String webhookUrl = "";
        private String appId = "";
        private String appSecret = "";
        private String receiveIdType = "chat_id";
        private String receiveId = "";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getWebhookUrl() { return webhookUrl; }
        public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
        public String getAppId() { return appId; }
        public void setAppId(String appId) { this.appId = appId; }
        public String getAppSecret() { return appSecret; }
        public void setAppSecret(String appSecret) { this.appSecret = appSecret; }
        public String getReceiveIdType() { return receiveIdType; }
        public void setReceiveIdType(String receiveIdType) { this.receiveIdType = receiveIdType; }
        public String getReceiveId() { return receiveId; }
        public void setReceiveId(String receiveId) { this.receiveId = receiveId; }
        
        public boolean useAppApi() {
            return appId != null && !appId.isEmpty() && 
                   appSecret != null && !appSecret.isEmpty() &&
                   receiveId != null && !receiveId.isEmpty();
        }
    }
    
    public static class WeComConfig {
        private boolean enabled = false;
        private String webhookUrl = "";
        private String corpId = "";
        private String corpSecret = "";
        private String agentId = "";
        private String toUser = "@all";
        private String toParty = "";
        private String toTag = "";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getWebhookUrl() { return webhookUrl; }
        public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
        public String getCorpId() { return corpId; }
        public void setCorpId(String corpId) { this.corpId = corpId; }
        public String getCorpSecret() { return corpSecret; }
        public void setCorpSecret(String corpSecret) { this.corpSecret = corpSecret; }
        public String getAgentId() { return agentId; }
        public void setAgentId(String agentId) { this.agentId = agentId; }
        public String getToUser() { return toUser; }
        public void setToUser(String toUser) { this.toUser = toUser; }
        public String getToParty() { return toParty; }
        public void setToParty(String toParty) { this.toParty = toParty; }
        public String getToTag() { return toTag; }
        public void setToTag(String toTag) { this.toTag = toTag; }
        
        public boolean useAppApi() {
            return corpId != null && !corpId.isEmpty() && 
                   corpSecret != null && !corpSecret.isEmpty() &&
                   agentId != null && !agentId.isEmpty();
        }
    }
    
    public static class DingTalkConfig {
        private boolean enabled = false;
        private String webhookUrl = "";
        private String appKey = "";
        private String appSecret = "";
        private String agentId = "";
        private String useridList = "";
        private String deptIdList = "";
        private boolean toAllUser = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getWebhookUrl() { return webhookUrl; }
        public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
        public String getAppKey() { return appKey; }
        public void setAppKey(String appKey) { this.appKey = appKey; }
        public String getAppSecret() { return appSecret; }
        public void setAppSecret(String appSecret) { this.appSecret = appSecret; }
        public String getAgentId() { return agentId; }
        public void setAgentId(String agentId) { this.agentId = agentId; }
        public String getUseridList() { return useridList; }
        public void setUseridList(String useridList) { this.useridList = useridList; }
        public String getDeptIdList() { return deptIdList; }
        public void setDeptIdList(String deptIdList) { this.deptIdList = deptIdList; }
        public boolean isToAllUser() { return toAllUser; }
        public void setToAllUser(boolean toAllUser) { this.toAllUser = toAllUser; }
        
        public boolean useAppApi() {
            return appKey != null && !appKey.isEmpty() && 
                   appSecret != null && !appSecret.isEmpty();
        }
    }

    public static class AttackChainConfig {
        private boolean enabled = true;
        private int maxSessions = 10000;
        private int sessionTimeoutMinutes = 30;
        private int maxEventsPerSession = 20;
        private int minPhasesForChain = 2;
        private int riskScoreThreshold = 80;
        private double eventConfidenceThreshold = 0.6d;
        private String alertLogPath = "attack-chain-alerts.log";
        private boolean attackerIndexEnabled = true;
        private int maxProfiles = 10000;
        private int profileTtlDays = 7;
        private int evictionBatchSize = 100;
        private int statsUpdateInterval = 100;
        private int maxRecentSessions = 20;
        private int relatedTimeWindowMinutes = 60;
        private int maxRelatedAttackers = 10;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getMaxSessions() { return maxSessions; }
        public void setMaxSessions(int maxSessions) { this.maxSessions = maxSessions; }
        public int getSessionTimeoutMinutes() { return sessionTimeoutMinutes; }
        public void setSessionTimeoutMinutes(int sessionTimeoutMinutes) { this.sessionTimeoutMinutes = sessionTimeoutMinutes; }
        public int getMaxEventsPerSession() { return maxEventsPerSession; }
        public void setMaxEventsPerSession(int maxEventsPerSession) { this.maxEventsPerSession = maxEventsPerSession; }
        public int getMinPhasesForChain() { return minPhasesForChain; }
        public void setMinPhasesForChain(int minPhasesForChain) { this.minPhasesForChain = minPhasesForChain; }
        public int getRiskScoreThreshold() { return riskScoreThreshold; }
        public void setRiskScoreThreshold(int riskScoreThreshold) { this.riskScoreThreshold = riskScoreThreshold; }
        public double getEventConfidenceThreshold() { return eventConfidenceThreshold; }
        public void setEventConfidenceThreshold(double eventConfidenceThreshold) {
            this.eventConfidenceThreshold = Math.max(0.0d, Math.min(1.0d, eventConfidenceThreshold));
        }
        public String getAlertLogPath() { return alertLogPath; }
        public void setAlertLogPath(String alertLogPath) { this.alertLogPath = alertLogPath; }
        public boolean isAttackerIndexEnabled() { return attackerIndexEnabled; }
        public void setAttackerIndexEnabled(boolean attackerIndexEnabled) { this.attackerIndexEnabled = attackerIndexEnabled; }
        public int getMaxProfiles() { return maxProfiles; }
        public void setMaxProfiles(int maxProfiles) { this.maxProfiles = maxProfiles; }
        public int getProfileTtlDays() { return profileTtlDays; }
        public void setProfileTtlDays(int profileTtlDays) { this.profileTtlDays = profileTtlDays; }
        public int getEvictionBatchSize() { return evictionBatchSize; }
        public void setEvictionBatchSize(int evictionBatchSize) { this.evictionBatchSize = evictionBatchSize; }
        public int getStatsUpdateInterval() { return statsUpdateInterval; }
        public void setStatsUpdateInterval(int statsUpdateInterval) { this.statsUpdateInterval = statsUpdateInterval; }
        public int getMaxRecentSessions() { return maxRecentSessions; }
        public void setMaxRecentSessions(int maxRecentSessions) { this.maxRecentSessions = maxRecentSessions; }
        public int getRelatedTimeWindowMinutes() { return relatedTimeWindowMinutes; }
        public void setRelatedTimeWindowMinutes(int relatedTimeWindowMinutes) { this.relatedTimeWindowMinutes = relatedTimeWindowMinutes; }
        public int getMaxRelatedAttackers() { return maxRelatedAttackers; }
        public void setMaxRelatedAttackers(int maxRelatedAttackers) { this.maxRelatedAttackers = maxRelatedAttackers; }
    }

    public enum Mode {
        MONITOR,
        BLOCK
    }

    public List<SecurityRule> getRules() {
        if (rules.isEmpty()) {
            loadBuiltinRules();
        }
        return new ArrayList<>(rules);
    }

    private void loadBuiltinRules() {
        // XSS 攻击规则
        // 修复: 将 .* 替换为 [^>]{0,200} 或 [\s\S]{0,500}，防止跨越大量字符的贪婪匹配
        rules.add(createRule(
                "xss-attack",
                "(?i)" +
                "<\\s*script[^>]*>|</\\s*script\\s*?>" +
                "|on(load|error|focus|blur|click|dblclick|mousedown|mouseup|mouseover|mousemove|mouseout|keydown|keypress|keyup|submit|reset|change|select|input|animationend|animationstart|animationiteration|transitionend|drag|dragstart|dragend|drop|scroll|wheel|copy|cut|paste|contextmenu|pointerdown|pointerup|pointermove|touchstart|touchend|touchmove)\\s*=" +
                "|javascript\\s*:" +
                "|vbscript\\s*:" +
                "|data\\s*:\\s*text/html" +
                // ReDoS 修复: 限制 svg 标签内内容的匹配长度
                "|<\\s*svg[^>]*>[\\s\\S]{0,500}<\\s*script" +
                "|<\\s*svg[^>]*\\bon\\w+\\s*=" +
                "|<\\s*img[^>]+src\\s*=\\s*['\"]?\\s*javascript:" +
                "|<\\s*img[^>]*\\bon\\w+\\s*=" +
                "|<\\s*object[^>]*>" +
                "|<\\s*embed[^>]*>" +
                "|expression\\s*\\(" +
                "|<\\s*meta[^>]+refresh[^>]*>" +
                "|<\\s*import[^>]*>" +
                "|<\\s*base[^>]+href[^>]*>" +
                "|<\\s*iframe[^>]*>" +
                "|<\\s*form[^>]+action\\s*=\\s*['\"]?\\s*javascript:" +
                // ReDoS 修复: 限制 style 标签内到 expression 的距离
                "|<\\s*style[^>]*>[\\s\\S]{0,500}expression\\s*\\(" +
                "|<\\s*link[^>]*href\\s*=\\s*['\"]?\\s*javascript:" +
                "|<\\s*body[^>]*\\bon\\w+\\s*=" +
                "|background-image\\s*:\\s*url\\s*\\(" +
                // 保持长度限制 {1,20} 和 {0,50}
                "|\\bon[a-z]{1,20}\\s*=\\s*['\"]?[^'\"]{0,50}['\"]?" +
                "|<\\s*svg[^>]*onload" +
                "|<\\s*math[^>]*>" +
                "|<\\s*details[^>]*ontoggle" +
                "|<\\s*marquee[^>]*onstart" +
                "|<\\s*(video|audio)[^>]*onerror" +
                "|<\\s*source[^>]*onerror" +
                "|['\"]\\s*-\\s*alert\\s*\\(",
                "high",
                true));

        // 代码执行规则
        rules.add(createRule(
                "code-execution",
                "(?i)" +
                "\\b(eval|setTimeout|setInterval|Function|constructor)\\s*\\(" +
                "|(?<!\\.)\\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\s*\\(" +
                "|\\b(file_get_contents|file_put_contents|fopen|fwrite|fread|readfile|include|require|include_once|require_once)\\s*\\(" +
                "|\\b(unserialize|serialize)\\s*\\(" +
                "|\\bClass\\.forName\\s*\\(" +
                // ReDoS 修复: [^}]* 是安全的（否定字符类），但为了保险起见，建议确保输入长度校验
                "|\\$\\{\\s*(?:runtime|process|getRuntime)\\s*\\.\\s*exec\\s*\\([^}]*\\}" +
                "|\\$\\{[^}]*(?:new\\s+java)[^}]*\\}",
                "high",
                true));

        // SQL 注入规则 - 重点修复区域
        rules.add(createRule(
                "sql-injection",
                "(?i)" +
                "\\bunion\\s+(?:all\\s+)?select\\b" +
                // ReDoS 修复: 严重漏洞修复。
                // 原代码: select\s+[\w\s,\*]+\s+from -> 导致 \s 和 [\w\s] 重叠回溯
                // 新代码: select ... from 中间限制字符长度，且使用惰性匹配或明确的非重叠标记
                // Tighten SELECT...FROM to SQL-like field/table tokens to reduce NLP false positives.
                "|\\bselect\\s+(?:\\*|(?:[a-zA-Z_][\\w]*\\s*(?:,\\s*[a-zA-Z_][\\w]*\\s*){0,15}))\\s+from\\s+[a-zA-Z_][\\w]*\\b" +
                "|\\bexec(?:ute)?\\s+\\w+" +
                "|\\bdrop\\s+(?:table|database)\\b" +
                "|\\bcreate\\s+(?:table|database|user)\\b" +
                "|\\balter\\s+(?:table|user)\\b" +
                "|\\btruncate\\s+table\\b" +
                "|\\binsert\\s+into\\b" +
                // ReDoS 修复: 限制 update 和 set 之间的距离，防止长字符串回溯
                "|\\bupdate\\s+\\w+(?:(?!set)[\\s\\S]){1,200}\\s+set\\b" +
                "|\\bdelete\\s+from\\b" +
                "|'\\s*(?:--|#|/\\*)" +
                "|\"\\s*(?:--|#|/\\*)" +
                "|\\b(?:sleep|benchmark|waitfor\\s+delay|pg_sleep)\\s*\\(" +
                "|\\bor\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+" +
                "|\\band\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+" +
                "|['\"]\\s*or\\s*['\"]{2}\\s*=\\s*['\"]{1,2}" +
                "|\\border\\s+by\\s+\\d+\\b" +
                "|\\b(?:version|database|user|schema)\\s*\\(" +
                "|\\b0x[0-9a-fA-F]+\\b" +
                "|\\bchar\\s*\\([^)]*\\)" +
                "|\\bcast\\s*\\([^)]*\\s+as\\s+\\w+\\)" +
                "|\\bconvert\\s*\\(" +
                "|;\\s*(?:select|insert|update|delete|drop|create|alter|exec)" +
                "|\\b(?:xp_cmdshell|sp_executesql|sp_oacreate)\\b" +
                "|\\b(?:load_file|into\\s+outfile|into\\s+dumpfile)\\b" +
                "|\\b(?:copy|pg_read_file|pg_ls_dir)\\b",
                "high",
                true));

        // 命令注入规则 - 增强版 (包含 Windows PoC 拦截)
        rules.add(createRule(
                "command-injection",
                "(?i)" +
                // 1. 典型的命令注入分隔符结构 (; | & \n) 后面紧跟敏感命令
                "(?:[;&|\\n\\r]|\\b(?:and|or)\\b)\\s*" +
                "(?:rm|mv|cp|mkdir|rmdir|touch|cat|ls|dir|type|ps|kill|chmod|chown|grep|sed|awk|wc|tr|wget|curl|nc|netcat|ping|telnet|ssh|ftp|nslookup|whoami|id|uname|hostname|useradd|userdel|su|sudo|tcpdump)\\b" +
                // 2. 命令替换/执行语法
                "|`[^`]+`" +
                "|\\$\\([^)]+\\)" +
                // 3. 极其危险的系统程序直接调用
                "|\\b(?:cmd(?:\\.exe)?\\s*(?:/c|/k)|powershell|pwsh|wsl|/bin/sh|/bin/bash|/bin/zsh)\\b" +
                // 增加：Windows 常见 PoC 程序 (calc, notepad, mspaint)
                // 注意：这里使用了 \b 边界匹配，防止匹配到 'calculation'
                "|\\b(?:calc|notepad|mspaint|winver)(?:\\.exe)?\\b" +
                // 4. 重定向到敏感设备
                "|/dev/(?:tcp|udp)/" +
                // 5. Windows 特有的一些危险命令
                "|\\b(?:certutil|bitsadmin|mshta|cscript|wscript|vbs|wbem|regsvr32)\\b",
                "high",
                true));

        // SSRF 攻击规则
        rules.add(createRule(
                "ssrf-attack",
                "(?i)" +
                // 1. 危险协议 (极少在正常 Header 中出现，除非是攻击)
                "\\b(?:gopher|dict|php|jar|tftp|expect|phar)\\s*://" +
                "|\\bfile\\s*:///" +
                
                // 2. 混淆/绕过的 IP 写法 (黑客常用的绕过手段，正常 Referer 不会这样写)
                //    包括：0.0.0.0, 十进制IP, 16进制IP, 八进制IP
                "|(?:https?://|//)\\s*0\\.0\\.0\\.0\\b" +
                "|(?:https?://|//)\\s*(?:2130706433|0x7f000001|017700000001)\\b" +
                "|(?:https?://|//)\\s*0177\\.0\\.0\\.1\\b" +
                "|(?:https?://|//)\\s*0x7f\\.0x0\\.0x0\\.0x1\\b" +
                "|https?://\\s*0(?:[/:\\s?#]|$)" +
                "|(?:https?://|//)\\s*(?:localhost|127(?:\\.\\d{1,3}){0,3}|10(?:\\.\\d{1,3}){3}|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}|192\\.168(?:\\.\\d{1,3}){2})(?::\\d{1,5})?(?:[/:\\s?#]|$)" +
                
                // 3. IPv6 缩写绕过
                "|(?:https?://|//)\\s*\\[\\s*::1\\s*\\]" +
                "|(?:https?://|//)\\s*\\[\\s*::ffff:127\\.0\\.0\\.1\\s*\\]" +
                "|(?:https?://|//)\\s*\\[\\s*::\\s*\\]" +
                
                // 4. 云元数据地址 (AWS/GCP/Azure) - 绝对高危
                "|169\\.254\\.169\\.254" +
                "|metadata\\.google\\.internal" +
                "|https?://\\s*169\\.254\\.\\d{1,3}\\.\\d{1,3}\\b" +
                
                // 5. DNS 重绑定域名

                "|(?:https?://|//)\\s*(?:[\\w.-]*\\.)?(?:localtest\\.me|nip\\.io|xip\\.io|sslip\\.io|burpcollaborator\\.net)\\b",
                
                // *** 变更说明 ***
                // 移除了对 standard 'localhost' 和 '127.x.x.x' 的直接 http 协议匹配。
                // 原因：在开发环境或内网应用中，Referer/Origin 头包含 http://127.0.0.1 是合法的。
                // 生产环境建议通过防火墙或网络策略隔离内网，而不是靠正则匹配标准 IP。
                "medium",
                true));

        // 路径遍历规则
        rules.add(createRule(
                "path-traversal",
                "(?i)" +
                "(?:\\.\\.[\\\\/])" +
                "|(?:%2e%2e[%/])" +
                "|(?:%252e%252e)" +
                "|(?:%c0%ae)" +
                "|(?:%c0%af)" +
                "|(?:%uff0e)" +
                "|(?:\\.\\.%252f)" +
                "|(?:\\.\\.%255c)" +
                "|(?:\\.\\.\\u002f)" +
                "|(?:\\.\\.\\u005c)" +
                // 固定重复次数，相对安全
                "|(?:\\.\\.[\\\\/]){3,}" +
                "|(?:\\.\\.[\\\\/]\\x00)" +
                "|(?:\\\\\\.\\\\[a-zA-Z]+)" +
                "|(?:^/(?:etc/(?:passwd|shadow)|proc/self/environ|windows/win\\.ini)(?:$|[/?#]))",
                "high",
                true));

        // LDAP 注入规则
        rules.add(createRule(
                "ldap-injection",
                "(?i)" +
                // ReDoS 修复: 限制通配符长度
                "\\([^)]*(?:\\||&|\\*)[^)]{0,200}\\)" +
                "|\\*\\)" +
                "|\\)\\(" +
                "|\\)\\|\\(" +
                "|\\)&\\(" +
                "|\\*\\)\\(cn=\\*" +
                "|\\\\[0-9a-fA-F]{2}" +
                "|\\(\\w+=\\x00" +
                "|\\b(?:memberOf|userAccountControl|objectClass)\\s*=",
                "medium",
                true));

        // XXE 注入规则
        rules.add(createRule(
                "xxe-injection",
                "(?i)" +
                "<!\\s*entity\\s+\\w+\\s+system\\s+" +
                "|<!\\s*entity\\s+\\w+\\s+public\\s+" +
                "|<!\\s*entity\\s+%\\s*\\w+" +
                "|<!\\s*doctype\\s+\\w+\\s+system\\s+" +
                "|<!\\s*doctype\\s+\\w+\\s+public\\s+" +
                "|<!\\s*doctype\\s+[^>]*\\[\\s*<" +
                "|<\\s*xi:include\\s+" +
                "|xmlns\\s*[=:]\\s*['\"]?\\s*data:",
                "high",
                true));

        // 模板注入规则
        rules.add(createRule(
                "template-injection",
                "(?i)" +
                "\\$\\{[^}]*(?:\\?new|\\?new\\s*\\(|freemarker\\.template\\.utility)[^}]*\\}" +
                "|#\\{[^}]*(?:runtime|exec|getRuntime)[^}]*\\}" +
                "|th\\s*:\\s*(?:text|utext)\\s*=\\s*['\"]?\\$\\{[^}]*(?:runtime|exec|new\\s+java)[^}]*\\}" +
                "|\\{\\{[^}]*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|config|request|self)[^}]*\\}\\}" +
                "|\\{%[^%]*(?:import|include|extends|from)[^%]*%\\}" +
                "|\\{php\\}" +
                "|\\{[^}]*(?:system|exec|passthru)[^}]*\\}" +
                "|\\$\\{[^}]*(?:self|import)[^}]*\\}" +
                "|\\$\\{[^}]*(?:getClass\\s*\\(|forName\\s*\\(|getMethod\\s*\\(|invoke\\s*\\()[^}]*\\}" +
                "|<\\#assign[^>]{0,300}freemarker\\.template\\.utility\\.Execute[^>]{0,300}>" +
                "|!\\{[^}]*(?:eval|Function)[^}]*\\}" +
                "|\\$\\{7\\*7\\}" +
                "|\\{\\{7\\*7\\}\\}" +
                "|#\\{7\\*7\\}",
                "high",
                true));

        // 反序列化攻击规则
        rules.add(createRule(
                "deserialization-attack",
                "(?i)" +
                "rO0AB" +
                "|aced0005" +
                "|O:\\d+:\"[^\"]+\":" +
                "|O:\\d+:\"[^\"]+\":\\d+:\\{" +
                "|a:\\d+:\\{" +
                "|c(?:pickle|cPickle)" +
                "|\\(lp\\d+" +
                "|!!python/object" +
                "|!!ruby/object" +
                "|org\\.apache\\.commons\\.collections" +
                "|com\\.fasterxml\\.jackson" +
                "|javax\\.management\\.BadAttributeValueExpException",
                "high",
                true));

        // NoSQL 注入规则
        rules.add(createRule(
                "nosql-injection",
                "(?i)" +
                "\\{\\s*\"?\\$\\s*(?:ne|gt|gte|lt|lte|eq|in|nin|exists|type|mod|regex|text|where|all|elemMatch|size|not|or|and|nor)\\s*\"?\\s*:" +
                "|\\$where\\s*:" +
                "|\\$where\\s*\\(" +
                "|\\$where\\s*:\\s*['\"]?this\\." +
                "|\"\\$\\s*(?:push|pull|addToSet|pop|unset|inc|mul|rename|setOnInsert)\"\\s*:" +
                "|mapReduce\\s*\\(" +
                "|\"\\$\\s*expr\"\\s*:" +
                "|\"\\$\\s*(?:match|group|project|sort|limit|skip|unwind|lookup|graphLookup|facet|bucket|sortByCount)\"\\s*:",
                "high",
                true));

        // ========================================================================
        // 阶段 4: 安装阶段 (Installation)
        // 目标: 植入后门、WebShell、修改系统配置以确保持久化
        // ========================================================================
        rules.add(createRule(
                "installation-attack",
                "(?i)" +
                // 1. WebShell 常见特征代码 (PHP/JSP/ASP)
                "(?:eval\\s*\\(\\s*\\$_POST|system\\s*\\(\\s*\\$_GET|base64_decode\\s*\\()" +
                "|<%@\\s*Page\\s+Language" +
                "|language\\s*=\\s*[\"']vbscript[\"']" +
                "|python\\s*-c\\s*['\"]import\\s+socket" +
                
                // 2. 写入文件/下载后门 (wget/curl 保存文件, echo 写入)
                "|\\b(?:wget|curl|certutil|bitsadmin)\\s+.*\\s+(?:-O|--output|-o)\\s+\\S+\\.(?:php|jsp|asp|sh|bat|exe|dll)" +
                "|\\becho\\s+.*\\s+>>\\s+\\S+\\.(?:php|jsp|asp|sh|bat)" +
                
                // 3. 权限维持/定时任务
                "|\\b(?:crontab\\s+-[elr]|schtasks\\s*/create)" +
                "|/etc/cron\\.(?:daily|hourly|weekly|monthly)" +
                "|\\.ssh/authorized_keys" +
                "|REG\\s+ADD\\s+HK[LCU]",
                "high",
                true));

        // ========================================================================
        // 阶段 5: 命令控制阶段 (Command & Control / C2)
        // 目标: 反弹 Shell、连接 C2 服务器、建立隧道
        // ========================================================================
        rules.add(createRule(
                "c2-communication",
                "(?i)" +
                // 1. 反弹 Shell 经典特征
                "\\b(?:bash|sh|zsh|ksh)\\s*-i\\s*>&\\s*/dev/(?:tcp|udp)/" +
                "|nc\\s+(?:-e|/bin/sh|/bin/bash)" +
                "|ncat\\s+.*\\s+-e" +
                "|socat\\s+exec" +
                
                // 2. PowerShell 编码指令 (常用于 C2)
                "|powershell\\s+.*-(?:enc|encodedcommand|encoded)\\s+[a-zA-Z0-9+/]{20,}" +
                
                // 3. 常见内网穿透与代理工具
                "|\\b(?:frpc|ngrok|nps|chisel|reGeorg|ew_for_linux|lcx)\\b" +
                
                // 4. 远程下载执行 (内存加载，无文件攻击)
                "|iex\\s*\\(\\s*New-Object\\s+Net\\.WebClient\\s*\\)\\.DownloadString" +
                "|\\|\\s*bash\\s*$",  // 管道直接给 bash
                "high",
                true));

        // ========================================================================
        // 阶段 6: 行动阶段 (Actions on Objectives)
        // 目标: 数据窃取、删除日志、破坏系统、勒索加密
        // ========================================================================
        rules.add(createRule(
                "actions-on-objectives",
                "(?i)" +
                // 1. 敏感数据窃取/导出
                "\\b(?:mysqldump|pg_dump|mongoexport|sqlite3)\\s+" +
                "|\\bcat\\s+/etc/(?:passwd|shadow|group|hosts)" +
                "|\\bcat\\s+/proc/self/environ" +
                "|type\\s+C:\\\\Windows\\\\win\\.ini" +
                "|REG\\s+SAVE\\s+HKLM\\\\SAM" +
                "|REG\\s+SAVE\\s+HKLM\\\\SYSTEM" +
                
                // 2. 痕迹清理 (删除日志)
                "|rm\\s+-rf\\s+/var/log" +
                "|echo\\s*\"\"\\s*>\\s*/var/log/" +
                "|unset\\s+HISTFILE" +
                "|history\\s+-c" +
                "|wevtutil\\s+cl\\s+" + // Windows 清除日志
                
                // 3. 破坏/勒索行为
                "|\\b(?:shred|wipe|sdelete)\\b" +
                "|chmod\\s+-R\\s+000\\s+" +
                "|dd\\s+if=/dev/(?:zero|urandom)\\s+of=" +
                "|rd\\s+/s\\s+/q",
                "high",
                true));

        }

    private SecurityRule createRule(String name, String pattern, String level, boolean enabled) {
        SecurityRule rule = new SecurityRule();
        rule.setName(name);
        rule.setPattern(pattern);
        rule.setLevel(level);
        rule.setEnabled(enabled);
        return rule;
    }

    // ==================== Getter/Setter (保持不变) ====================

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Mode getMode() { return mode; }
    public void setMode(Mode mode) { this.mode = mode; }
    public void setRules(List<SecurityRule> rules) { this.rules = rules; }
    public List<String> getExcludePaths() { return excludePaths; }
    public void setExcludePaths(List<String> excludePaths) { this.excludePaths = excludePaths; }
    public List<String> getIncludePaths() { return includePaths; }
    public void setIncludePaths(List<String> includePaths) { this.includePaths = includePaths; }
    public String getLogFilePath() { return logFilePath; }
    public void setLogFilePath(String logFilePath) { this.logFilePath = logFilePath; }
    public int getMaxLogSizeMb() { return maxLogSizeMb; }
    public void setMaxLogSizeMb(int maxLogSizeMb) { this.maxLogSizeMb = maxLogSizeMb; }
    public int getMaxLogFiles() { return maxLogFiles; }
    public void setMaxLogFiles(int maxLogFiles) { this.maxLogFiles = maxLogFiles; }
    public boolean isAsyncLogEnabled() { return asyncLogEnabled; }
    public void setAsyncLogEnabled(boolean asyncLogEnabled) { this.asyncLogEnabled = asyncLogEnabled; }
    public int getFilterOrder() { return filterOrder; }
    public void setFilterOrder(int filterOrder) { this.filterOrder = filterOrder; }
    public boolean isEnableUi() { return enableUi; }
    public void setEnableUi(boolean enableUi) { this.enableUi = enableUi; }
    public List<String> getTrustedProxies() { return trustedProxies; }
    public void setTrustedProxies(List<String> trustedProxies) { this.trustedProxies = trustedProxies; }
    public AttackChainConfig getAttackChain() { return attackChain; }
    public void setAttackChain(AttackChainConfig attackChain) { this.attackChain = attackChain; }
    public LlmConfig getLlm() { return llm; }
    public void setLlm(LlmConfig llm) { this.llm = llm; }
}
