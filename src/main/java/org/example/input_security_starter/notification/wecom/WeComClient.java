package org.example.input_security_starter.notification;

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
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 企业微信客户端
 * 支持两种方式：
 * 1. 群机器人Webhook（简单，适合群通知）
 * 2. 企业微信应用API（强大，支持私聊、Markdown消息）
 */
public class WeComClient {

    private static final Logger log = LoggerFactory.getLogger(WeComClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final String TOKEN_API = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";
    private static final String MESSAGE_API = "https://qyapi.weixin.qq.com/cgi-bin/message/send";

    private final String webhookUrl;
    private final String corpId;
    private final String corpSecret;
    private final String agentId;
    private final String toUser;
    private final String toParty;
    private final String toTag;
    private final boolean enabled;
    private final boolean useAppApi;

    private final AtomicReference<String> cachedToken = new AtomicReference<>();
    private final AtomicLong tokenExpireTime = new AtomicLong(0);

    public WeComClient(String webhookUrl, boolean enabled) {
        this(webhookUrl, null, null, null, null, null, null, enabled);
    }

    public WeComClient(String webhookUrl, String corpId, String corpSecret,
                       String agentId, String toUser, String toParty, String toTag, boolean enabled) {
        this.webhookUrl = webhookUrl;
        this.corpId = corpId;
        this.corpSecret = corpSecret;
        this.agentId = agentId;
        this.toUser = toUser != null ? toUser : "@all";
        this.toParty = toParty;
        this.toTag = toTag;
        this.enabled = enabled;
        this.useAppApi = corpId != null && !corpId.isEmpty() &&
                         corpSecret != null && !corpSecret.isEmpty() &&
                         agentId != null && !agentId.isEmpty();

        if (enabled) {
            if (useAppApi) {
                log.info("WeComClient initialized with App API: corpId={}, agentId={}, toUser={}",
                        maskCorpId(corpId), agentId, this.toUser);
            } else if (webhookUrl != null && !webhookUrl.isEmpty()) {
                log.info("WeComClient initialized with Webhook: {}", maskWebhookUrl(webhookUrl));
            } else {
                log.info("WeComClient enabled but no valid configuration");
            }
        } else {
            log.info("WeComClient disabled");
        }
    }

    /**
     * 发送文本消息
     */
    public boolean sendTextMessage(String text) {
        if (!enabled) {
            log.debug("WeCom notification disabled, skipping message");
            return false;
        }

        if (useAppApi) {
            return sendTextMessageViaAppApi(text);
        } else {
            return sendTextMessageViaWebhook(text);
        }
    }

    /**
     * 发送Markdown消息
     */
    public boolean sendMarkdownMessage(String content) {
        if (!enabled) {
            log.debug("WeCom notification disabled, skipping message");
            return false;
        }

        if (useAppApi) {
            return sendMarkdownMessageViaAppApi(content);
        } else {
            return sendMarkdownMessageViaWebhook(content);
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
        message.put("msgtype", "text");

        Map<String, String> content = new HashMap<>();
        content.put("content", text);
        message.put("text", content);

        return sendToWebhook(webhookUrl, message);
    }

    /**
     * 通过Webhook发送Markdown消息
     */
    private boolean sendMarkdownMessageViaWebhook(String content) {
        if (webhookUrl == null || webhookUrl.isEmpty()) {
            log.warn("Webhook URL not configured");
            return false;
        }

        Map<String, Object> message = new HashMap<>();
        message.put("msgtype", "markdown");

        Map<String, String> markdown = new HashMap<>();
        markdown.put("content", content);
        message.put("markdown", markdown);

        return sendToWebhook(webhookUrl, message);
    }

    /**
     * 通过应用API发送文本消息
     */
    private boolean sendTextMessageViaAppApi(String text) {
        try {
            String token = getAccessToken();
            if (token == null) {
                log.error("Failed to get access token");
                return false;
            }

            Map<String, Object> message = new HashMap<>();
            message.put("touser", toUser);
            if (toParty != null && !toParty.isEmpty()) {
                message.put("toparty", toParty);
            }
            if (toTag != null && !toTag.isEmpty()) {
                message.put("totag", toTag);
            }
            message.put("msgtype", "text");
            message.put("agentid", Integer.parseInt(agentId));

            Map<String, String> textContent = new HashMap<>();
            textContent.put("content", text);
            message.put("text", textContent);

            return sendMessageViaAppApi(token, message);
        } catch (Exception e) {
            log.error("Failed to send text message via App API: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 通过应用API发送Markdown消息
     */
    private boolean sendMarkdownMessageViaAppApi(String content) {
        try {
            String token = getAccessToken();
            if (token == null) {
                log.error("Failed to get access token");
                return false;
            }

            Map<String, Object> message = new HashMap<>();
            message.put("touser", toUser);
            if (toParty != null && !toParty.isEmpty()) {
                message.put("toparty", toParty);
            }
            if (toTag != null && !toTag.isEmpty()) {
                message.put("totag", toTag);
            }
            message.put("msgtype", "markdown");
            message.put("agentid", Integer.parseInt(agentId));

            Map<String, String> markdown = new HashMap<>();
            markdown.put("content", content);
            message.put("markdown", markdown);

            return sendMessageViaAppApi(token, message);
        } catch (Exception e) {
            log.error("Failed to send markdown message via App API: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 获取access_token
     */
    private String getAccessToken() {
        if (cachedToken.get() != null && System.currentTimeMillis() < tokenExpireTime.get()) {
            log.debug("Using cached access token");
            return cachedToken.get();
        }

        HttpURLConnection conn = null;
        try {
            String urlStr = TOKEN_API + "?corpid=" + corpId + "&corpsecret=" + corpSecret;
            log.info("Requesting access token from: {}", TOKEN_API);
            log.debug("CorpId: {}, CorpSecret: {}****", corpId, corpSecret.substring(0, Math.min(4, corpSecret.length())));
            
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int statusCode = conn.getResponseCode();
            log.info("Token API response status: {}", statusCode);

            if (statusCode == 200) {
                java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                log.info("Token API response: {}", response.toString());
                
                JsonNode root = objectMapper.readTree(response.toString());
                
                if (root.has("errcode") && root.get("errcode").asInt() != 0) {
                    log.error("Token API returned error: errcode={}, errmsg={}", 
                            root.get("errcode").asInt(), 
                            root.has("errmsg") ? root.get("errmsg").asText() : "unknown");
                    return null;
                }
                
                if (root.has("access_token")) {
                    String token = root.get("access_token").asText();
                    int expire = root.has("expires_in") ? root.get("expires_in").asInt() : 7200;

                    cachedToken.set(token);
                    tokenExpireTime.set(System.currentTimeMillis() + (expire - 60) * 1000L);

                    log.info("Access token obtained successfully, expires in {} seconds", expire);
                    return token;
                } else {
                    log.error("Token not found in response: {}", response);
                    return null;
                }
            } else {
                java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
                StringBuilder errorResponse = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    errorResponse.append(line);
                }
                log.error("Failed to get access token, status: {}, error: {}", statusCode, errorResponse);
                return null;
            }
        } catch (Exception e) {
            log.error("Failed to get access token: {}", e.getMessage(), e);
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
    private boolean sendMessageViaAppApi(String token, Map<String, Object> message) {
        HttpURLConnection conn = null;
        try {
            String urlStr = MESSAGE_API + "?access_token=" + token;
            log.info("Sending message to WeCom App API: {}", MESSAGE_API);
            
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            String jsonPayload = objectMapper.writeValueAsString(message);

            log.info("Message payload: {}", jsonPayload);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int statusCode = conn.getResponseCode();
            log.info("Message API response status: {}", statusCode);

            if (statusCode == 200) {
                java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                log.info("Message API response: {}", response.toString());
                
                JsonNode root = objectMapper.readTree(response.toString());
                int errcode = root.has("errcode") ? root.get("errcode").asInt() : -1;

                if (errcode == 0) {
                    log.info("Message sent to WeCom successfully via App API");
                    return true;
                } else {
                    log.error("Failed to send message to WeCom App API, errcode: {}, errmsg: {}",
                            errcode, root.has("errmsg") ? root.get("errmsg").asText() : "unknown");
                    return false;
                }
            } else {
                java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
                StringBuilder errorResponse = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    errorResponse.append(line);
                }
                log.error("Failed to send message to WeCom App API, status: {}, error: {}", statusCode, errorResponse);
                return false;
            }
        } catch (Exception e) {
            log.error("Failed to send message to WeCom App API: {}", e.getMessage(), e);
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

            log.debug("Sending message to WeCom Webhook: {}", jsonPayload);

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
                int errcode = root.has("errcode") ? root.get("errcode").asInt() : -1;

                if (errcode == 0) {
                    log.info("Message sent to WeCom successfully via Webhook");
                    return true;
                } else {
                    log.error("Failed to send message to WeCom Webhook, errcode: {}, errmsg: {}",
                            errcode, root.has("errmsg") ? root.get("errmsg").asText() : "unknown");
                    return false;
                }
            } else {
                log.error("Failed to send message to WeCom Webhook, status code: {}", statusCode);
                return false;
            }
        } catch (Exception e) {
            log.error("Failed to send message to WeCom Webhook: {}", e.getMessage(), e);
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 测试连接
     */
    public boolean testConnection() {
        if (!enabled) {
            log.warn("WeCom notification not enabled");
            return false;
        }

        return sendTextMessage("🔍 企业微信机器人连接测试成功\n\n这是来自Input Security Starter的测试消息。");
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
            String key = url.substring(lastSlash + 1);
            if (key.length() > 8) {
                return url.substring(0, lastSlash + 1) + key.substring(0, 4) + "****" + key.substring(key.length() - 4);
            }
        }
        return url;
    }

    /**
     * 遮蔽Corp ID
     */
    private String maskCorpId(String corpId) {
        if (corpId == null || corpId.length() < 8) {
            return corpId;
        }
        return corpId.substring(0, 4) + "****" + corpId.substring(corpId.length() - 4);
    }

    public boolean isEnabled() {
        return enabled && (useAppApi || (webhookUrl != null && !webhookUrl.isEmpty()));
    }

    public boolean isUseAppApi() {
        return useAppApi;
    }
}
