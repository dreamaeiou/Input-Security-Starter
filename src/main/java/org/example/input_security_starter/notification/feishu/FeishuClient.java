package org.example.input_security_starter.notification.feishu;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 飞书客户端
 * 支持两种方式：
 * 1. 自定义机器人Webhook（简单，适合群通知）
 * 2. 飞书应用API（强大，支持私聊、卡片消息、交互）
 */
public class FeishuClient {

    private static final Logger log = LoggerFactory.getLogger(FeishuClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final String WEBHOOK_API = "https://open.feishu.cn/open-apis/bot/v2/hook/";
    private static final String TOKEN_API = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal";
    private static final String MESSAGE_API = "https://open.feishu.cn/open-apis/im/v1/messages";

    private final String webhookUrl;
    private final String appId;
    private final String appSecret;
    private final String receiveIdType;
    private final String receiveId;
    private final boolean enabled;
    private final boolean useAppApi;

    private final AtomicReference<String> cachedToken = new AtomicReference<>();
    private final AtomicLong tokenExpireTime = new AtomicLong(0);

    public FeishuClient(String webhookUrl, boolean enabled) {
        this(webhookUrl, null, null, null, null, enabled);
    }

    public FeishuClient(String webhookUrl, String appId, String appSecret, 
                        String receiveIdType, String receiveId, boolean enabled) {
        this.webhookUrl = webhookUrl;
        this.appId = appId;
        this.appSecret = appSecret;
        this.receiveIdType = receiveIdType != null ? receiveIdType : "chat_id";
        this.receiveId = receiveId;
        this.enabled = enabled;
        this.useAppApi = appId != null && !appId.isEmpty() && 
                         appSecret != null && !appSecret.isEmpty() &&
                         receiveId != null && !receiveId.isEmpty();

        if (enabled) {
            if (useAppApi) {
                log.info("FeishuClient initialized with App API: appId={}, receiveIdType={}, receiveId={}", 
                        maskAppId(appId), this.receiveIdType, receiveId);
            } else if (webhookUrl != null && !webhookUrl.isEmpty()) {
                log.info("FeishuClient initialized with Webhook: {}", maskWebhookUrl(webhookUrl));
            } else {
                log.info("FeishuClient enabled but no valid configuration");
            }
        } else {
            log.info("FeishuClient disabled");
        }
    }

    /**
     * 发送文本消息
     */
    public boolean sendTextMessage(String text) {
        if (!enabled) {
            log.debug("Feishu notification disabled, skipping message");
            return false;
        }

        if (useAppApi) {
            return sendTextMessageViaAppApi(text);
        } else {
            return sendTextMessageViaWebhook(text);
        }
    }

    /**
     * 发送交互式卡片消息
     */
    public boolean sendCardMessage(String title, String content) {
        if (!enabled) {
            log.debug("Feishu notification disabled, skipping message");
            return false;
        }

        if (useAppApi) {
            return sendCardMessageViaAppApi(title, content);
        } else {
            return sendCardMessageViaWebhook(title, content);
        }
    }

    /**
     * 通过Webhook发送文本消息
     */
    private boolean sendTextMessageViaWebhook(String text) {
        if (webhookUrl == null || webhookUrl.isEmpty()) {
            log.warn("Webhook URL not configured");
            return false;
        }

        Map<String, Object> message = new HashMap<>();
        message.put("msg_type", "text");
        
        Map<String, String> content = new HashMap<>();
        content.put("text", text);
        message.put("content", content);

        return sendToWebhook(webhookUrl, message);
    }

    /**
     * 通过Webhook发送卡片消息
     */
    private boolean sendCardMessageViaWebhook(String title, String content) {
        if (webhookUrl == null || webhookUrl.isEmpty()) {
            log.warn("Webhook URL not configured");
            return false;
        }

        Map<String, Object> message = new HashMap<>();
        message.put("msg_type", "interactive");
        
        Map<String, Object> card = new HashMap<>();
        card.put("header", createCardHeader(title));
        
        Map<String, Object> element = new HashMap<>();
        element.put("tag", "markdown");
        element.put("content", content);
        
        card.put("elements", new Object[]{element});
        message.put("card", card);

        return sendToWebhook(webhookUrl, message);
    }

    /**
     * 通过应用API发送文本消息
     */
    private boolean sendTextMessageViaAppApi(String text) {
        try {
            String token = getTenantAccessToken();
            if (token == null) {
                log.error("Failed to get tenant access token");
                return false;
            }

            Map<String, Object> content = new HashMap<>();
            content.put("text", text);

            return sendMessageViaAppApi(token, "text", objectMapper.writeValueAsString(content));
        } catch (Exception e) {
            log.error("Failed to send text message via App API: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 通过应用API发送卡片消息
     */
    private boolean sendCardMessageViaAppApi(String title, String content) {
        try {
            String token = getTenantAccessToken();
            if (token == null) {
                log.error("Failed to get tenant access token");
                return false;
            }

            Map<String, Object> card = new HashMap<>();
            card.put("header", createCardHeader(title));
            
            Map<String, Object> element = new HashMap<>();
            element.put("tag", "markdown");
            element.put("content", content);
            
            card.put("elements", new Object[]{element});

            return sendMessageViaAppApi(token, "interactive", objectMapper.writeValueAsString(card));
        } catch (Exception e) {
            log.error("Failed to send card message via App API: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 获取tenant_access_token
     */
    private String getTenantAccessToken() {
        if (cachedToken.get() != null && System.currentTimeMillis() < tokenExpireTime.get()) {
            return cachedToken.get();
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(TOKEN_API);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            Map<String, String> request = new HashMap<>();
            request.put("app_id", appId);
            request.put("app_secret", appSecret);

            String jsonPayload = objectMapper.writeValueAsString(request);
            
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int statusCode = conn.getResponseCode();
            
            if (statusCode == 200) {
                java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                
                JsonNode root = objectMapper.readTree(response.toString());
                if (root.has("tenant_access_token")) {
                    String token = root.get("tenant_access_token").asText();
                    int expire = root.has("expire") ? root.get("expire").asInt() : 7200;
                    
                    cachedToken.set(token);
                    tokenExpireTime.set(System.currentTimeMillis() + (expire - 60) * 1000L);
                    
                    log.debug("Tenant access token obtained, expires in {} seconds", expire);
                    return token;
                } else {
                    log.error("Token not found in response: {}", response);
                    return null;
                }
            } else {
                log.error("Failed to get tenant access token, status code: {}", statusCode);
                return null;
            }
        } catch (Exception e) {
            log.error("Failed to get tenant access token: {}", e.getMessage(), e);
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 通过应用API发送消息
     */
    private boolean sendMessageViaAppApi(String token, String msgType, String content) {
        HttpURLConnection conn = null;
        try {
            String urlStr = MESSAGE_API + "?receive_id_type=" + receiveIdType;
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            Map<String, Object> message = new HashMap<>();
            message.put("receive_id", receiveId);
            message.put("msg_type", msgType);
            message.put("content", content);
            message.put("uuid", UUID.randomUUID().toString());

            String jsonPayload = objectMapper.writeValueAsString(message);
            
            log.debug("Sending message to Feishu App API: {}", jsonPayload);
            
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int statusCode = conn.getResponseCode();
            
            if (statusCode == 200) {
                log.info("Message sent to Feishu successfully via App API");
                return true;
            } else {
                java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                log.error("Failed to send message to Feishu App API, status: {}, response: {}", statusCode, response);
                return false;
            }
        } catch (Exception e) {
            log.error("Failed to send message to Feishu App API: {}", e.getMessage(), e);
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 发送消息到Webhook
     */
    private boolean sendToWebhook(String webhookUrl, Map<String, Object> message) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(webhookUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            String jsonPayload = objectMapper.writeValueAsString(message);
            
            log.debug("Sending message to Feishu Webhook: {}", jsonPayload);
            
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int statusCode = conn.getResponseCode();
            
            if (statusCode == 200) {
                log.info("Message sent to Feishu successfully via Webhook");
                return true;
            } else {
                log.error("Failed to send message to Feishu Webhook, status code: {}", statusCode);
                return false;
            }
        } catch (Exception e) {
            log.error("Failed to send message to Feishu Webhook: {}", e.getMessage(), e);
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 创建卡片头部
     */
    private Map<String, Object> createCardHeader(String title) {
        Map<String, Object> header = new HashMap<>();
        header.put("title", createTextElement(title, "plain_text"));
        header.put("template", "red");
        return header;
    }

    /**
     * 创建文本元素
     */
    private Map<String, Object> createTextElement(String text, String tag) {
        Map<String, Object> element = new HashMap<>();
        element.put("content", text);
        element.put("tag", tag);
        return element;
    }

    /**
     * 测试连接
     */
    public boolean testConnection() {
        if (!enabled) {
            log.warn("Feishu notification not enabled");
            return false;
        }

        return sendTextMessage("🔍 飞书机器人连接测试成功\n\n这是来自Input Security Starter的测试消息。");
    }

    /**
     * 遮蔽Webhook URL中的敏感信息
     */
    private String maskWebhookUrl(String url) {
        if (url == null || url.length() < 30) {
            return url;
        }
        int lastSlash = url.lastIndexOf('/');
        if (lastSlash > 0 && lastSlash < url.length()) {
            String token = url.substring(lastSlash + 1);
            if (token.length() > 8) {
                return url.substring(0, lastSlash + 1) + token.substring(0, 4) + "****" + token.substring(token.length() - 4);
            }
        }
        return url;
    }

    /**
     * 遮蔽App ID
     */
    private String maskAppId(String appId) {
        if (appId == null || appId.length() < 8) {
            return appId;
        }
        return appId.substring(0, 4) + "****" + appId.substring(appId.length() - 4);
    }

    public boolean isEnabled() {
        return enabled && (useAppApi || (webhookUrl != null && !webhookUrl.isEmpty()));
    }

    public boolean isUseAppApi() {
        return useAppApi;
    }
}
