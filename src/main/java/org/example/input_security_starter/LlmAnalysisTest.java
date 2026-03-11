package org.example.input_security_starter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.analysis.AlertAggregator;
import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.llm.analysis.LlmAnalysisService;
import org.example.input_security_starter.llm.ip.AbuseIpDbClient;
import org.example.input_security_starter.llm.ip.IpQueryService;
import org.example.input_security_starter.llm.provider.LlmProvider;
import org.example.input_security_starter.llm.provider.aliyun.AliyunBailianConfig;
import org.example.input_security_starter.llm.provider.aliyun.AliyunBailianProvider;
import org.example.input_security_starter.llm.provider.glm.GlmConfig;
import org.example.input_security_starter.llm.provider.glm.GlmProvider;
import org.example.input_security_starter.notification.FeishuClient;
import org.example.input_security_starter.notification.FeishuNotifier;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * LLM 分析功能测试类
 * 用于测试 GLM API、阿里百炼 API 连接、IP查询和聚合分析功能
 */
public class LlmAnalysisTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void main(String[] args) {
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
                System.err.println("  - FEISHU_APP_ID: 飞书应用 ID");
                System.err.println("  - FEISHU_APP_SECRET: 飞书应用密钥");
                System.err.println("  - FEISHU_RECEIVE_ID_TYPE: 飞书接收者类型 (默认 user_id)");
                System.err.println("  - FEISHU_RECEIVE_ID: 飞书接收者 ID");
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
                .filter(a -> a.getRiskScore() >= 70).count());
        System.out.println("  中风险IP数：" + aggregationResult.getAggregatedAlerts().stream()
                .filter(a -> a.getRiskScore() >= 40 && a.getRiskScore() < 70).count());
        System.out.println("  低风险IP数：" + aggregationResult.getAggregatedAlerts().stream()
                .filter(a -> a.getRiskScore() < 40).count());

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
        System.out.println("  App ID: " + feishuAppId);
        System.out.println("  接收类型: " + feishuReceiveIdType);
        System.out.println("  接收ID: " + feishuReceiveId);
        
        System.out.println("\n【步骤9】初始化 LLM 分析服务...");
        LlmAnalysisService service = new LlmAnalysisService(llmProvider, abuseIpDbClient, ipQueryService, alertLogPath, 50, feishuNotifier);
        System.out.println("  ✓ LlmAnalysisService 初始化完成");

        System.out.println("\n【步骤10】开始 LLM 分析 (" + provider + ")...");
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
        
        System.out.println("\n【步骤11】检查飞书通知状态...");
        if (feishuNotifier.isEnabled()) {
            System.out.println("  ✓ 飞书通知已自动发送（在分析过程中自动触发）");
        } else {
            System.out.println("  ⚠ 飞书通知未启用");
        }

        System.out.println("\n╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║                        LLM 分析报告                             ║");
        System.out.println("║                    (Provider: " + provider + ")");
        System.out.println("╚════════════════════════════════════════════════════════════════╝\n");

        System.out.println("报告 ID: " + report.getReportId());
        System.out.println("分析时间: " + report.getAnalysisTime());
        System.out.println("告警数量: " + report.getAlertCount());
        System.out.println("IP 情报数: " + report.getIpIntelligenceCount());
        System.out.println("状态: " + report.getStatus());
        
        if (report.getErrorMessage() != null) {
            System.out.println("错误信息: " + report.getErrorMessage());
        }
        
        System.out.println("\n--- 分析摘要 ---");
        System.out.println(report.getSummary());

        if (!report.getRecommendations().isEmpty()) {
            System.out.println("\n--- 防御建议 ---");
            for (int i = 0; i < report.getRecommendations().size(); i++) {
                System.out.println((i + 1) + ". " + report.getRecommendations().get(i));
            }
        }

        if (!report.getKeyIndicators().isEmpty()) {
            System.out.println("\n--- 关键指标 ---");
            System.out.println(String.join(", ", report.getKeyIndicators()));
        }

        System.out.println("\n--- 完整分析报告 ---");
        System.out.println(report.getAttackNarrative());

        System.out.println("\n【步骤12】检查IP索引状态...");
        System.out.println("  索引条目数: " + ipQueryService.getIndexSize());
        
        File indexFile = new File(ipLogDir, "ip_index.json");
        if (indexFile.exists()) {
            System.out.println("  索引文件: " + indexFile.getAbsolutePath() + " (" + indexFile.length() + " bytes)");
        }

        System.out.println("\n【步骤13】关闭服务...");
        ipQueryService.shutdown();
        System.out.println("  ✓ IpQueryService 已关闭");

        System.out.println("\n╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║                      测试完成                                   ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
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
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
