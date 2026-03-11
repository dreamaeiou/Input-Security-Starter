package org.example.input_security_starter;

import org.example.input_security_starter.notification.WeComClient;

/**
 * 企业微信连接测试类
 * 用于快速验证企业微信配置是否正确
 */
public class WeComConnectionTest {

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║              企业微信连接测试                                    ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝\n");

        String wecomWebhookUrl = getEnvOrDefault("WECOM_WEBHOOK_URL", "");
        String wecomCorpId = getEnvOrDefault("WECOM_CORP_ID", "");
        String wecomCorpSecret = getEnvOrDefault("WECOM_CORP_SECRET", "");
        String wecomAgentId = getEnvOrDefault("WECOM_AGENT_ID", "");
        String wecomToUser = getEnvOrDefault("WECOM_TO_USER", "@all");
        String wecomToParty = getEnvOrDefault("WECOM_TO_PARTY", "");
        String wecomToTag = getEnvOrDefault("WECOM_TO_TAG", "");

        System.out.println("【配置信息】");
        System.out.println("  WECOM_WEBHOOK_URL: " + (wecomWebhookUrl.isEmpty() ? "未配置" : wecomWebhookUrl.substring(0, Math.min(50, wecomWebhookUrl.length())) + "..."));
        System.out.println("  WECOM_CORP_ID: " + (wecomCorpId.isEmpty() ? "未配置" : wecomCorpId));
        System.out.println("  WECOM_CORP_SECRET: " + (wecomCorpSecret.isEmpty() ? "未配置" : wecomCorpSecret.substring(0, 4) + "****"));
        System.out.println("  WECOM_AGENT_ID: " + (wecomAgentId.isEmpty() ? "未配置" : wecomAgentId));
        System.out.println("  WECOM_TO_USER: " + wecomToUser);
        System.out.println();

        boolean useAppApi = !wecomCorpId.isEmpty() && !wecomCorpSecret.isEmpty() && !wecomAgentId.isEmpty();
        
        if (!useAppApi && wecomWebhookUrl.isEmpty()) {
            System.err.println("错误：未配置有效的企业微信通知方式");
            System.err.println("\n请配置以下环境变量之一：");
            System.err.println("\n方式一：群机器人 Webhook");
            System.err.println("  WECOM_WEBHOOK_URL=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx");
            System.err.println("\n方式二：企业微信应用 API");
            System.err.println("  WECOM_CORP_ID=your_corp_id");
            System.err.println("  WECOM_CORP_SECRET=your_corp_secret");
            System.err.println("  WECOM_AGENT_ID=your_agent_id");
            return;
        }

        System.out.println("【初始化客户端】");
        WeComClient client = new WeComClient(
            wecomWebhookUrl,
            wecomCorpId,
            wecomCorpSecret,
            wecomAgentId,
            wecomToUser,
            wecomToParty,
            wecomToTag,
            true
        );
        
        System.out.println("  客户端启用状态: " + client.isEnabled());
        System.out.println("  使用应用API模式: " + client.isUseAppApi());
        System.out.println();

        System.out.println("【发送测试消息】");
        boolean result = client.testConnection();
        
        System.out.println();
        if (result) {
            System.out.println("✓ 企业微信连接测试成功！请检查是否收到消息。");
        } else {
            System.err.println("✗ 企业微信连接测试失败！请检查配置是否正确。");
        }
    }

    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
