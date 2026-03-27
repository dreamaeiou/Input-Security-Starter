package org.example.input_security_starter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.analysis.AlertAggregator;
import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.llm.analysis.LlmAnalysisService;
import org.example.input_security_starter.llm.ip.AbuseIpDbClient;
import org.example.input_security_starter.llm.ip.IpQueryService;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.llm.provider.LlmProviderConfig;
import org.example.input_security_starter.llm.provider.aliyun.AliyunBailianConfig;
import org.example.input_security_starter.llm.provider.aliyun.AliyunBailianProvider;
import org.example.input_security_starter.llm.provider.glm.GlmConfig;
import org.example.input_security_starter.llm.provider.glm.GlmProvider;
import org.example.input_security_starter.notification.feishu.FeishuClient;
import org.example.input_security_starter.notification.feishu.FeishuNotifier;
import org.example.input_security_starter.notification.wecom.WeComClient;
import org.example.input_security_starter.notification.wecom.WeComNotifier;
import org.example.input_security_starter.notification.dingtalk.DingTalkClient;
import org.example.input_security_starter.notification.dingtalk.DingTalkNotifier;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * LLM 分析功能测试类
 * 用于测试 GLM API、阿里百炼 API 连接、IP查询和聚合分析功能
 */
public class LlmAnalysisTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final SimpleDateFormat REPORT_TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final int HIGH_RISK_THRESHOLD = 80;
    private static final int MEDIUM_RISK_THRESHOLD = 50;

    public static void main(String[] args) {
        loadEnvFile();
        
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║              LLM 分析功能完整测试                               ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝\n");

        String provider = getEnvOrDefault("LLM_PROVIDER", "glm");
        String alertLogPath = "attack-chain-alerts.log";
        String ipLogDir = ".";
        String abuseIpDbApiKey = getEnvOrDefault("ABUSEIPDB_API_KEY", "");
        
        String feishuAppId = getEnvOrDefault("FEISHU_APP_ID", "");
        String feishuAppSecret = getEnvOrDefault("FEISHU_APP_SECRET", "");
        String feishuReceiveIdType = getEnvOrDefault("FEISHU_RECEIVE_ID_TYPE", "user_id");
        String feishuReceiveId = getEnvOrDefault("FEISHU_RECEIVE_ID", "");
        
        String wecomWebhookUrl = getEnvOrDefault("WECOM_WEBHOOK_URL", "");
        String wecomCorpId = getEnvOrDefault("WECOM_CORP_ID", "");
        String wecomCorpSecret = getEnvOrDefault("WECOM_CORP_SECRET", "");
        String wecomAgentId = getEnvOrDefault("WECOM_AGENT_ID", "");
        String wecomToUser = getEnvOrDefault("WECOM_TO_USER", "@all");
        String wecomToParty = getEnvOrDefault("WECOM_TO_PARTY", "");
        String wecomToTag = getEnvOrDefault("WECOM_TO_TAG", "");
        
        String dingtalkWebhookUrl = getEnvOrDefault("DINGTALK_WEBHOOK_URL", "");
        String dingtalkAppKey = getEnvOrDefault("DINGTALK_APP_KEY", "");
        String dingtalkAppSecret = getEnvOrDefault("DINGTALK_APP_SECRET", "");
        String dingtalkAgentId = getEnvOrDefault("DINGTALK_AGENT_ID", "");
        String dingtalkUseridList = getEnvOrDefault("DINGTALK_USERID_LIST", "");
        String dingtalkDeptIdList = getEnvOrDefault("DINGTALK_DEPT_ID_LIST", "");
        boolean dingtalkToAllUser = Boolean.parseBoolean(getEnvOrDefault("DINGTALK_TO_ALL_USER", "true"));

        String apiKey;
        String model;
        
        if ("aliyun-bailian".equalsIgnoreCase(provider)) {
            apiKey = getEnvOrDefault("ALIYUN_BAILIAN_API_KEY", "");
            model = getEnvOrDefault("ALIYUN_BAILIAN_MODEL", "qwen-plus");
            
            if (apiKey.isEmpty()) {
                System.err.println("错误：未设置 ALIYUN_BAILIAN_API_KEY 环境变量");
                System.err.println("\n请设置以下环境变量：");
                System.err.println("  - LLM_PROVIDER: aliyun-bailian");
                System.err.println("  - ALIYUN_BAILIAN_API_KEY: 阿里百炼 API Key");
                System.err.println("  - ALIYUN_BAILIAN_MODEL: 模型名称 (可选，默认 qwen-plus)");
                return;
            }
        } else {
            apiKey = getEnvOrDefault("GLM_API_KEY", "");
            model = getEnvOrDefault("GLM_MODEL", "glm-4-flash");
            
            if (apiKey.isEmpty()) {
                System.err.println("错误：未设置 GLM_API_KEY 环境变量");
                System.err.println("\n请设置以下环境变量：");
                System.err.println("  - LLM_PROVIDER: glm 或 aliyun-bailian");
                System.err.println("  - GLM_API_KEY: 智谱 AI GLM API Key");
                System.err.println("  - GLM_MODEL: 模型名称 (可选，默认 glm-4-flash)");
                System.err.println("\n或者使用阿里百炼：");
                System.err.println("  - LLM_PROVIDER: aliyun-bailian");
                System.err.println("  - ALIYUN_BAILIAN_API_KEY: 阿里百炼 API Key");
                System.err.println("  - ALIYUN_BAILIAN_MODEL: 模型名称 (可选，默认 qwen-plus)");
                System.err.println("\n可选环境变量：");
                System.err.println("  - ABUSEIPDB_API_KEY: AbuseIPDB API Key");
                System.err.println("\n飞书通知：");
                System.err.println("  - FEISHU_APP_ID: 飞书应用 ID");
                System.err.println("  - FEISHU_APP_SECRET: 飞书应用密钥");
                System.err.println("  - FEISHU_RECEIVE_ID_TYPE: 飞书接收者类型 (默认 user_id)");
                System.err.println("  - FEISHU_RECEIVE_ID: 飞书接收者 ID");
                System.err.println("\n企业微信通知：");
                System.err.println("  - WECOM_WEBHOOK_URL: 企业微信群机器人 Webhook URL");
                System.err.println("  - WECOM_CORP_ID: 企业微信企业 ID (应用API模式)");
                System.err.println("  - WECOM_CORP_SECRET: 企业微信应用密钥 (应用API模式)");
                System.err.println("  - WECOM_AGENT_ID: 企业微信应用 ID (应用API模式)");
                System.err.println("  - WECOM_TO_USER: 接收用户ID (默认 @all)");
                System.err.println("  - WECOM_TO_PARTY: 接收部门ID");
                System.err.println("  - WECOM_TO_TAG: 接收标签ID");
                System.err.println("\n钉钉通知：");
                System.err.println("  - DINGTALK_WEBHOOK_URL: 钉钉群机器人 Webhook URL");
                System.err.println("  - DINGTALK_APP_SECRET: 钉钉机器人签名密钥 (可选)");
                System.err.println("  - DINGTALK_APP_KEY: 钉钉企业应用 Key (应用API模式)");
                System.err.println("  - DINGTALK_APP_SECRET: 钉钉企业应用密钥 (应用API模式)");
                System.err.println("  - DINGTALK_AGENT_ID: 钉钉应用 ID (应用API模式)");
                System.err.println("  - DINGTALK_TO_USER: 接收用户ID");
                System.err.println("  - DINGTALK_TO_PARTY: 接收部门ID");
                return;
            }
        }

        File logFile = new File(alertLogPath);
        if (!logFile.exists()) {
            System.err.println("错误：日志文件不存在：" + alertLogPath);
            System.err.println("\n请先运行测试生成日志文件:");
            System.err.println("  mvn test -Dtest=AttackChainLogGeneratorTest#generateComprehensiveAttackLog");
            return;
        }

        if (logFile.length() == 0) {
            System.err.println("错误：日志文件为空：" + alertLogPath);
            return;
        }

        System.out.println("【步骤1】初始化 LLM 客户端...");
        System.out.println("  提供商: " + provider);
        System.out.println("  模型: " + model);
        System.out.println("  API Key: " + apiKey.substring(0, Math.min(10, apiKey.length())) + "...");

        LlmProvider llmProvider;
        if ("aliyun-bailian".equalsIgnoreCase(provider)) {
            AliyunBailianConfig config = new AliyunBailianConfig(null, apiKey, model);
            llmProvider = new AliyunBailianProvider(config);
        } else {
            GlmConfig config = new GlmConfig(null, apiKey, model);
            llmProvider = new GlmProvider(config);
        }

        System.out.println("\n【步骤2】测试 LLM API 连接...");
        boolean connected = llmProvider.testConnection();
        if (connected) {
            System.out.println("  ✓ " + provider + " API 连接成功!");
        } else {
            System.err.println("  ✗ " + provider + " API 连接失败");
            return;
        }

        AbuseIpDbClient abuseIpDbClient = new AbuseIpDbClient(null, abuseIpDbApiKey, 90);
        System.out.println("  ✓ AbuseIPDB 客户端初始化完成");

        IpQueryService ipQueryService = new IpQueryService(abuseIpDbClient, ipLogDir);
        System.out.println("  ✓ IpQueryService 初始化完成 (日志目录: " + ipLogDir + ")");

        System.out.println("\n【步骤3】读取告警日志...");
        List<String> alertLogs = readAlertLogs(logFile);
        System.out.println("  日志文件：" + alertLogPath);
        System.out.println("  文件大小：" + logFile.length() + " bytes");
        System.out.println("  告警数量：" + alertLogs.size());

        System.out.println("\n【步骤4】测试告警聚合功能...");
        AlertAggregator aggregator = new AlertAggregator(ipQueryService, 50);
        
        long aggregateStart = System.currentTimeMillis();
        AlertAggregator.AggregationResult aggregationResult = aggregator.aggregate(alertLogs);
        long aggregateEnd = System.currentTimeMillis();

        System.out.println("  聚合耗时：" + (aggregateEnd - aggregateStart) + " ms");
        System.out.println("  原始告警数：" + aggregationResult.getOriginalAlerts());
        System.out.println("  处理告警数：" + aggregationResult.getProcessedAlerts());
        System.out.println("  聚合后IP数：" + aggregationResult.getTotalIps());
        System.out.println("  总会话数：" + aggregationResult.getTotalSessions());
        System.out.println("  总事件数：" + aggregationResult.getTotalEvents());

        System.out.println("\n【步骤5】显示聚合结果摘要...");
        System.out.println("  高风险IP数：" + aggregationResult.getAggregatedAlerts().stream()
                .filter(a -> a.getRiskScore() >= HIGH_RISK_THRESHOLD).count());
        System.out.println("  中风险IP数：" + aggregationResult.getAggregatedAlerts().stream()
                .filter(a -> a.getRiskScore() >= MEDIUM_RISK_THRESHOLD && a.getRiskScore() < HIGH_RISK_THRESHOLD).count());
        System.out.println("  低风险IP数：" + aggregationResult.getAggregatedAlerts().stream()
                .filter(a -> a.getRiskScore() < MEDIUM_RISK_THRESHOLD).count());

        System.out.println("\n【步骤6】显示各IP聚合详情...");
        for (org.example.input_security_starter.llm.analysis.AggregatedAlert alert : aggregationResult.getAggregatedAlerts()) {
            System.out.println("\n  ┌─────────────────────────────────────────────────────────────┐");
            System.out.println("  │ IP: " + alert.getIp());
            System.out.println("  │ 风险评分: " + alert.getRiskScore());
            System.out.println("  │ 会话数: " + alert.getSessionCount() + " | 事件数: " + alert.getTotalEvents());
            System.out.println("  │ 攻击阶段: " + alert.getAttackPhases());
            System.out.println("  │ 攻击类型: " + alert.getAttackTypes());

            if (alert.getIpIntelligence() != null) {
                AbuseIpDbClient.IpIntelligence intel = alert.getIpIntelligence();
                System.out.println("  │ IP情报:");
                System.out.println("  │   - Abuse Score: " + intel.getAbuseConfidenceScore());
                System.out.println("  │   - 国家: " + intel.getCountryCode());
                System.out.println("  │   - ISP: " + intel.getIsp());
                System.out.println("  │   - TOR: " + (intel.isTor() ? "是" : "否"));
            }

            if (alert.getAsn() != null || alert.getProfileAttackCount() > 0) {
                System.out.println("  │ 攻击者画像:");
                if (alert.getAsn() != null) {
                    System.out.println("  │   - ASN: " + alert.getAsn());
                }
                if (alert.getCountry() != null && !alert.getCountry().isEmpty()) {
                    System.out.println("  │   - 国家: " + alert.getCountry());
                }
                if (alert.getProfileAttackCount() > 0) {
                    System.out.println("  │   - 累计攻击次数: " + alert.getProfileAttackCount());
                }
            }

            if (alert.getRelatedIps() != null && !alert.getRelatedIps().isEmpty()) {
                System.out.println("  │ 关联攻击者 (" + alert.getRelatedIps().size() + "):");
                int count = 0;
                for (String relatedIp : alert.getRelatedIps()) {
                    if (count++ >= 5) {
                        System.out.println("  │   ... 还有 " + (alert.getRelatedIps().size() - count + 1) + " 个");
                        break;
                    }
                    System.out.println("  │   - " + relatedIp);
                }
            }

            if (!alert.getTopPayloads().isEmpty()) {
                System.out.println("  │ 关键Payload:");
                int payloadCount = Math.min(3, alert.getTopPayloads().size());
                for (int i = 0; i < payloadCount; i++) {
                    String payload = alert.getTopPayloads().get(i);
                    if (payload.length() > 40) {
                        payload = payload.substring(0, 37) + "...";
                    }
                    System.out.println("  │   - " + payload);
                }
            }
            System.out.println("  └─────────────────────────────────────────────────────────────┘");
        }

        System.out.println("\n【步骤7】测试聚合数据JSON输出...");
        try {
            String aggregatedJson = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(aggregationResult.toMap());
            System.out.println("  JSON长度: " + aggregatedJson.length() + " 字符");
            System.out.println("  预览 (前500字符):");
            System.out.println("  " + aggregatedJson.substring(0, Math.min(500, aggregatedJson.length())) + "...");
        } catch (Exception e) {
            System.err.println("  ✗ JSON序列化失败: " + e.getMessage());
        }

        System.out.println("\n【步骤8】初始化飞书通知客户端...");
        FeishuClient feishuClient = new FeishuClient(
            null,
            feishuAppId,
            feishuAppSecret,
            feishuReceiveIdType,
            feishuReceiveId,
            true
        );
        FeishuNotifier feishuNotifier = new FeishuNotifier(feishuClient);
        System.out.println("  ✓ 飞书客户端初始化完成");
        System.out.println("  App ID: " + (feishuAppId.isEmpty() ? "未配置" : feishuAppId));
        System.out.println("  接收类型: " + feishuReceiveIdType);
        System.out.println("  接收ID: " + (feishuReceiveId.isEmpty() ? "未配置" : feishuReceiveId));
        
        System.out.println("\n【步骤9】初始化企业微信通知客户端...");
        boolean wecomUseAppApi = !wecomCorpId.isEmpty() && !wecomCorpSecret.isEmpty() && !wecomAgentId.isEmpty();
        WeComClient weComClient = new WeComClient(
            wecomWebhookUrl,
            wecomCorpId,
            wecomCorpSecret,
            wecomAgentId,
            wecomToUser,
            wecomToParty,
            wecomToTag,
            true
        );
        WeComNotifier weComNotifier = new WeComNotifier(weComClient);
        System.out.println("  ✓ 企业微信客户端初始化完成");
        System.out.println("  客户端启用状态: " + weComClient.isEnabled());
        System.out.println("  使用应用API模式: " + weComClient.isUseAppApi());
        if (wecomUseAppApi) {
            System.out.println("  模式: 应用API");
            System.out.println("  企业ID: " + wecomCorpId);
            System.out.println("  应用ID: " + wecomAgentId);
            System.out.println("  接收用户: " + wecomToUser);
        } else if (!wecomWebhookUrl.isEmpty()) {
            System.out.println("  模式: 群机器人Webhook");
            System.out.println("  Webhook: " + wecomWebhookUrl.substring(0, Math.min(50, wecomWebhookUrl.length())) + "...");
        } else {
            System.out.println("  模式: 未配置");
        }
        
        if (weComClient.isEnabled()) {
            System.out.println("\n【步骤9.1】测试企业微信连接...");
            boolean wecomTestResult = weComClient.testConnection();
            System.out.println("  企业微信连接测试: " + (wecomTestResult ? "成功" : "失败"));
        }
        
        System.out.println("\n【步骤9.2】初始化钉钉通知客户端...");
        boolean dingtalkUseAppApi = !dingtalkAppKey.isEmpty() && !dingtalkAppSecret.isEmpty();
        DingTalkClient dingTalkClient = new DingTalkClient(
            dingtalkWebhookUrl,
            dingtalkAppKey,
            dingtalkAppSecret,
            dingtalkAgentId,
            dingtalkUseridList,
            dingtalkDeptIdList,
            dingtalkToAllUser,
            true
        );
        DingTalkNotifier dingTalkNotifier = new DingTalkNotifier(dingTalkClient);
        System.out.println("  ✓ 钉钉客户端初始化完成");
        System.out.println("  客户端启用状态: " + dingTalkClient.isEnabled());
        System.out.println("  使用应用API模式: " + dingTalkClient.isUseAppApi());
        if (dingtalkUseAppApi) {
            System.out.println("  模式: 应用API");
            System.out.println("  App Key: " + dingtalkAppKey);
            System.out.println("  应用ID: " + dingtalkAgentId);
            System.out.println("  接收用户: " + dingtalkUseridList);
        } else if (!dingtalkWebhookUrl.isEmpty()) {
            System.out.println("  模式: 群机器人Webhook");
            System.out.println("  Webhook: " + dingtalkWebhookUrl.substring(0, Math.min(50, dingtalkWebhookUrl.length())) + "...");
        } else {
            System.out.println("  模式: 未配置");
        }
        
        if (dingTalkClient.isEnabled()) {
            System.out.println("\n【步骤9.3】测试钉钉连接...");
            boolean dingtalkTestResult = dingTalkClient.testConnection();
            System.out.println("  钉钉连接测试: " + (dingtalkTestResult ? "成功" : "失败"));
        }
        
        System.out.println("\n【步骤10】初始化 LLM 分析服务...");
        LlmAnalysisService service = new LlmAnalysisService(
            llmProvider, 
            abuseIpDbClient, 
            ipQueryService, 
            alertLogPath, 
            50, 
            24000,
            feishuNotifier,
            weComNotifier,
            dingTalkNotifier
        );
        System.out.println("  ✓ LlmAnalysisService 初始化完成");

        System.out.println("\n【步骤11】开始 LLM 分析 (" + provider + ")...");
        System.out.println("  (这可能需要几秒钟时间...)\n");

        long startTime = System.currentTimeMillis();
        AnalysisReport report = service.analyzeAttackChainAlerts();
        long endTime = System.currentTimeMillis();

        if (report == null) {
            System.err.println("  ✗ 分析失败：无法生成报告");
            ipQueryService.shutdown();
            return;
        }

        System.out.println("  ✓ 分析完成!");
        System.out.println("  耗时：" + (endTime - startTime) + " ms");
        
        System.out.println("\n【步骤12】检查通知状态...");
        if (feishuNotifier.isEnabled()) {
            System.out.println("  ✓ 飞书通知已自动发送");
        } else {
            System.out.println("  ⚠ 飞书通知未启用");
        }
        if (weComNotifier.isEnabled()) {
            System.out.println("  ✓ 企业微信通知已自动发送");
        } else {
            System.out.println("  ⚠ 企业微信通知未启用");
        }
        if (dingTalkNotifier.isEnabled()) {
            System.out.println("  ✓ 钉钉通知已自动发送");
        } else {
            System.out.println("  ⚠ 钉钉通知未启用");
        }

        System.out.println("\n╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║                        LLM 分析报告                             ║");
        System.out.println("║                    (Provider: " + provider + ")");
        System.out.println("╚════════════════════════════════════════════════════════════════╝\n");

        System.out.println("报告 ID: " + report.getReportId());
        System.out.println("分析时间: " + (report.getAnalysisTime() == null ? "未知" : REPORT_TIME_FORMAT.format(report.getAnalysisTime())));
        System.out.println("告警数量: " + report.getAlertCount());
        System.out.println("IP 情报数: " + report.getIpIntelligenceCount());
        System.out.println("状态: " + report.getStatus());
        
        if (report.getErrorMessage() != null) {
            System.out.println("错误信息: " + report.getErrorMessage());
        }
        
        System.out.println("\n--- 分析摘要 ---");
        System.out.println(report.getSummary());

        System.out.println("\n--- 攻击者画像 ---");
        System.out.println("技能等级: " + defaultText(report.getAttackerSkillLevel(), "未知"));
        System.out.println("自动化程度: " + defaultText(report.getAutomationType(), "未知"));
        System.out.println("主要意图: " + defaultText(report.getAttackerIntent(), "未知"));
        System.out.println("攻击模式: " + defaultText(report.getAttackerPattern(), "未知"));
        if (report.getAttackerIntentConfidence() > 0) {
            System.out.println("意图置信度: " + Math.round(report.getAttackerIntentConfidence() * 100) + "%");
        }

        List<AnalysisReport.PeerAttacker> peerAttackers = report.getPeerAttackers();
        if (peerAttackers != null && !peerAttackers.isEmpty()) {
            System.out.println("\n--- 关联攻击者 ---");
            int peerLimit = Math.min(5, peerAttackers.size());
            for (int i = 0; i < peerLimit; i++) {
                AnalysisReport.PeerAttacker peer = peerAttackers.get(i);
                String relation = peer.getRelationship() == null ? "unknown" : peer.getRelationship();
                int confidence = (int) Math.round(Math.max(0, Math.min(1, peer.getConfidence())) * 100.0);
                System.out.println(
                    (i + 1) + ". " + defaultText(peer.getIp(), "unknown")
                        + " | relationship=" + relation
                        + " | confidence=" + confidence + "%"
                );
            }
        }

        List<String> recommendations = report.getRecommendations() == null ? new ArrayList<String>() : report.getRecommendations();
        if (!recommendations.isEmpty()) {
            System.out.println("\n--- 防御建议 ---");
            for (int i = 0; i < recommendations.size(); i++) {
                String recommendation = recommendations.get(i);
                recommendation = recommendation == null ? "" : recommendation.trim().replaceAll("\\s+", " ");
                System.out.println((i + 1) + ". " + recommendation);
            }
        }

        List<String> keyIndicators = report.getKeyIndicators() == null ? new ArrayList<String>() : report.getKeyIndicators();
        if (!keyIndicators.isEmpty()) {
            System.out.println("\n--- 关键指标 ---");
            System.out.println(String.join(", ", keyIndicators));
        }

        System.out.println("\n--- 完整分析报告 ---");
        System.out.println(report.getAttackNarrative());

        System.out.println("\n[Compare Mode] Generating forced degraded report...");
        LlmAnalysisService degradedService = new LlmAnalysisService(
            new ForcedDegradedProvider("manual_compare_forced_degraded"),
            abuseIpDbClient,
            ipQueryService,
            alertLogPath,
            50,
            24000,
            null,
            null,
            null
        );
        long degradedStartTime = System.currentTimeMillis();
        AnalysisReport degradedReport = degradedService.analyzeAttackChainAlerts(false);
        long degradedEndTime = System.currentTimeMillis();
        if (degradedReport == null) {
            System.err.println("  [WARN] failed to generate degraded report");
        } else {
            System.out.println("  [OK] degraded report generated, cost: " + (degradedEndTime - degradedStartTime) + " ms");
            printReportToConsole("Degraded Report (Forced Fallback)", "forced-degraded", degradedReport);
        }

        if (degradedReport != null) {
            double normalUnifiedConfidence = normalizeConfidenceForManualCompare(report, aggregationResult);
            double degradedUnifiedConfidence = normalizeConfidenceForManualCompare(degradedReport, aggregationResult);
            System.out.println("\n--- Quick Compare ---");
            System.out.println("status: normal=" + report.getStatus() + " | degraded=" + degradedReport.getStatus());
            System.out.println("riskScore: normal=" + report.getRiskScore() + " | degraded=" + degradedReport.getRiskScore());
            System.out.println("riskLevel: normal=" + report.getRiskLevel() + " | degraded=" + degradedReport.getRiskLevel());
            System.out.println("confidence(original): normal=" + formatPercent(report.getConfidence())
                + " | degraded=" + formatPercent(degradedReport.getConfidence()));
            System.out.println("confidence(unified): normal=" + formatPercent(normalUnifiedConfidence)
                + " | degraded=" + formatPercent(degradedUnifiedConfidence));
            System.out.println("errorMessage: normal=" + defaultText(report.getErrorMessage(), "<none>")
                + " | degraded=" + defaultText(degradedReport.getErrorMessage(), "<none>"));
        }

        System.out.println("\n【步骤13】检查IP索引状态...");
        System.out.println("  索引条目数: " + ipQueryService.getIndexSize());
        
        File indexFile = new File(ipLogDir, "ip_index.json");
        if (indexFile.exists()) {
            System.out.println("  索引文件: " + indexFile.getAbsolutePath() + " (" + indexFile.length() + " bytes)");
        }

        System.out.println("\n【步骤14】关闭服务...");
        ipQueryService.shutdown();
        System.out.println("  ✓ IpQueryService 已关闭");

        System.out.println("\n╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║                      测试完成                                   ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
    }

    private static class ForcedDegradedProvider implements LlmProvider {
        private final String failureReason;
        private final LlmProviderConfig config = new ForcedDegradedConfig();

        ForcedDegradedProvider(String failureReason) {
            this.failureReason = failureReason;
        }

        @Override
        public String getName() {
            return "forced-degraded";
        }

        @Override
        public String analyze(String prompt) {
            return null;
        }

        @Override
        public String analyzeAggregatedAlerts(String aggregatedJson) {
            return null;
        }

        @Override
        public String analyzeAttackChain(List<String> alertLogs, Map<String, Object> ipIntelligence) {
            return null;
        }

        @Override
        public boolean testConnection() {
            return true;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public LlmProviderConfig getConfig() {
            return config;
        }

        @Override
        public String getLastFailureReason() {
            return failureReason;
        }
    }

    private static class ForcedDegradedConfig extends LlmProviderConfig {
        ForcedDegradedConfig() {
            this.apiUrl = "mock://forced-degraded";
            this.apiKey = "mock";
            this.model = "forced-degraded";
        }
    }

    private static void printReportToConsole(String title, String providerName, AnalysisReport report) {
        if (report == null) {
            System.out.println("\n===== " + title + " =====");
            System.out.println("报告为空，无法展示。");
            return;
        }

        System.out.println("\n==============================================================");
        System.out.println(title + " (Provider: " + providerName + ")");
        System.out.println("==============================================================");
        System.out.println("报告 ID: " + report.getReportId());
        System.out.println("分析时间: " + (report.getAnalysisTime() == null ? "未知" : REPORT_TIME_FORMAT.format(report.getAnalysisTime())));
        System.out.println("告警数量: " + report.getAlertCount());
        System.out.println("IP 情报数: " + report.getIpIntelligenceCount());
        System.out.println("状态: " + report.getStatus());
        if (report.getErrorMessage() != null) {
            System.out.println("错误信息: " + report.getErrorMessage());
        }
        System.out.println("\n--- 分析摘要 ---");
        System.out.println(report.getSummary());
        System.out.println("\n--- 攻击者画像 ---");
        System.out.println("技能等级: " + defaultText(report.getAttackerSkillLevel(), "未知"));
        System.out.println("自动化程度: " + defaultText(report.getAutomationType(), "未知"));
        System.out.println("主要意图: " + defaultText(report.getAttackerIntent(), "未知"));
        System.out.println("攻击模式: " + defaultText(report.getAttackerPattern(), "未知"));
        if (report.getAttackerIntentConfidence() > 0) {
            System.out.println("意图置信度: " + Math.round(report.getAttackerIntentConfidence() * 100) + "%");
        }

        List<AnalysisReport.PeerAttacker> peerAttackers = report.getPeerAttackers();
        if (peerAttackers != null && !peerAttackers.isEmpty()) {
            System.out.println("\n--- 关联攻击者 ---");
            int peerLimit = Math.min(5, peerAttackers.size());
            for (int i = 0; i < peerLimit; i++) {
                AnalysisReport.PeerAttacker peer = peerAttackers.get(i);
                String relation = peer.getRelationship() == null ? "unknown" : peer.getRelationship();
                int confidence = (int) Math.round(Math.max(0, Math.min(1, peer.getConfidence())) * 100.0);
                System.out.println(
                    (i + 1) + ". " + defaultText(peer.getIp(), "unknown")
                        + " | relationship=" + relation
                        + " | confidence=" + confidence + "%"
                );
            }
        }

        List<String> recommendations = report.getRecommendations() == null ? new ArrayList<String>() : report.getRecommendations();
        if (!recommendations.isEmpty()) {
            System.out.println("\n--- 防御建议 ---");
            for (int i = 0; i < recommendations.size(); i++) {
                String recommendation = recommendations.get(i);
                recommendation = recommendation == null ? "" : recommendation.trim().replaceAll("\\s+", " ");
                System.out.println((i + 1) + ". " + recommendation);
            }
        }

        List<String> keyIndicators = report.getKeyIndicators() == null ? new ArrayList<String>() : report.getKeyIndicators();
        if (!keyIndicators.isEmpty()) {
            System.out.println("\n--- 关键指标 ---");
            System.out.println(String.join(", ", keyIndicators));
        }

        System.out.println("\n--- 完整分析报告 ---");
        System.out.println(report.getAttackNarrative());
    }

    private static String formatPercent(double value) {
        double clamped = Math.max(0.0, Math.min(1.0, value));
        return String.valueOf(Math.round(clamped * 100.0)) + "%";
    }

    private static double normalizeConfidenceForManualCompare(
        AnalysisReport report,
        AlertAggregator.AggregationResult aggregationResult
    ) {
        if (report == null) {
            return 0.0;
        }

        int maxRisk = Math.max(0, Math.min(100, report.getRiskScore()));
        int highRisk = 0;
        int mediumRisk = 0;
        if (aggregationResult != null && aggregationResult.getAggregatedAlerts() != null) {
            for (org.example.input_security_starter.llm.analysis.AggregatedAlert alert : aggregationResult.getAggregatedAlerts()) {
                if (alert == null) {
                    continue;
                }
                int risk = Math.max(0, Math.min(100, alert.getRiskScore()));
                if (risk > maxRisk) {
                    maxRisk = risk;
                }
                if (risk >= HIGH_RISK_THRESHOLD) {
                    highRisk++;
                } else if (risk >= MEDIUM_RISK_THRESHOLD) {
                    mediumRisk++;
                }
            }
        }

        double riskFactor = maxRisk / 100.0;
        double estimated;
        if (report.isAttackDetected()) {
            estimated = 0.62 + (0.28 * riskFactor);
            if (highRisk > 0) {
                estimated += 0.05;
            } else if (mediumRisk > 0) {
                estimated += 0.02;
            }
            return Math.max(0.55, Math.min(0.95, estimated));
        }

        estimated = 0.45 + (0.20 * riskFactor);
        return Math.max(0.35, Math.min(0.80, estimated));
    }

    private static List<String> readAlertLogs(File logFile) {
        List<String> logs = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    logs.add(line);
                }
            }
        } catch (Exception e) {
            System.err.println("读取日志文件失败: " + e.getMessage());
        }
        return logs;
    }

    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        if (value == null || value.isEmpty()) {
            value = System.getProperty(key);
        }
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static String defaultText(String value, String fallback) {
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        return value.trim();
    }
    
    private static void loadEnvFile() {
        Properties props = new Properties();
        String[] envFiles = {".env", "../.env"};
        
        for (String envFile : envFiles) {
            try {
                File file = new File(envFile);
                if (file.exists()) {
                    try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                        props.load(reader);
                    }
                    for (String key : props.stringPropertyNames()) {
                        String value = props.getProperty(key);
                        if (System.getenv(key) == null || System.getenv(key).isEmpty()) {
                            System.setProperty(key, value);
                        }
                    }
                    System.out.println("  已从 " + envFile + " 加载环境变量");
                    return;
                }
            } catch (Exception e) {
            }
        }
    }
}
