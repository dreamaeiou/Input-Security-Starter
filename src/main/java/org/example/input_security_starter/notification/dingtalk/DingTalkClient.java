package org.example.input_security_starter.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 钉钉客户端
 * 支持两种方式：
 * 1. 自定义机器人Webhook（简单，适合群通知）
 * 2. 钉钉企业内部应用API（强大，支持私聊、Markdown消息）
 */
public class DingTalkClient {

    private static final Logger log = LoggerFactory.getLogger(DingTalkClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final String TOKEN_API = "https://oapi.dingtalk.com/gettoken";
    private static final String MESSAGE_API = "https://oapi.dingtalk.com/topapi/message/corpconversation/asyncsend_v2";

    private final String webhookUrl;
    private final String appKey;
    private final String appSecret;
    private final String agentId;
    private final String useridList;
    private final String deptIdList;
    private final boolean toAllUser;
    private final boolean enabled;
    private final boolean useAppApi;

    private final AtomicReference<String> cachedToken = new AtomicReference<>();
    private final AtomicLong tokenExpireTime = new AtomicLong(0);

    public DingTalkClient(String webhookUrl, boolean enabled) {
        this(webhookUrl, null, null, null, null, null, true, enabled);
    }

    public DingTalkClient(String webhookUrl, String appKey, String appSecret,
                          String agentId, String useridList, String deptIdList, boolean enabled) {
        this(webhookUrl, appKey, appSecret, agentId, useridList, deptIdList, true, enabled);
    }

    public DingTalkClient(String webhookUrl, String appKey, String appSecret,
                          String agentId, String useridList, String deptIdList, boolean toAllUser, boolean enabled) {
        this.webhookUrl = webhookUrl;
        this.appKey = appKey;
        this.appSecret = appSecret;
        this.agentId = agentId;
        this.useridList = useridList != null ? useridList : "";
        this.deptIdList = deptIdList != null ? deptIdList : "";
        this.toAllUser = toAllUser;
        this.enabled = enabled;
        this.useAppApi = appKey != null && !appKey.isEmpty() && 
                         appSecret != null && !appSecret.isEmpty();

        if (enabled) {
            if (useAppApi) {
                log.info("DingTalkClient initialized with App API: appKey={}, agentId={}", 
                        maskAppKey(appKey), agentId);
            } else if (webhookUrl != null && !webhookUrl.isEmpty()) {
                log.info("DingTalkClient initialized with Webhook");
            } else {
                log.info("DingTalkClient enabled but no valid configuration");
            }
        } else {
            log.info("DingTalkClient disabled");
        }
    }

    /**
     * 发送文本消息
     */
    public boolean sendTextMessage(String text) {
        if (!enabled) {
            log.debug("DingTalk notification disabled, skipping message");
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
    public boolean sendMarkdownMessage(String title, String content) {
        if (!enabled) {
            log.debug("DingTalk notification disabled, skipping message");
            return false;
        }

        if (useAppApi) {
            return sendMarkdownMessageViaAppApi(title, content);
        } else {
            return sendMarkdownMessageViaWebhook(title, content);
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

        try {
            Map<String, Object> message = new HashMap<>();
            message.put("msgtype", "text");
            
            Map<String, String> textContent = new HashMap<>();
            textContent.put("content", text);
            message.put("text", textContent);

            String urlWithSign = buildSignedWebhookUrl(webhookUrl);
            return sendToWebhook(urlWithSign, message);
        } catch (Exception e) {
            log.error("Failed to send text message via Webhook: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 通过Webhook发送Markdown消息
     */
    private boolean sendMarkdownMessageViaWebhook(String title, String content) {
        if (webhookUrl == null || webhookUrl.isEmpty()) {
            log.warn("Webhook URL not configured");
            return false;
        }

        try {
            Map<String, Object> message = new HashMap<>();
            message.put("msgtype", "markdown");
            
            Map<String, String> markdown = new HashMap<>();
            markdown.put("title", title);
            markdown.put("text", content);
            message.put("markdown", markdown);

            String urlWithSign = buildSignedWebhookUrl(webhookUrl);
            return sendToWebhook(urlWithSign, message);
        } catch (Exception e) {
            log.error("Failed to send markdown message via Webhook: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 构建带签名的Webhook URL
     * 钉钉Webhook支持签名验证，增强安全性
     */
    private String buildSignedWebhookUrl(String webhookUrl) throws Exception {
        if (appSecret == null || appSecret.isEmpty()) {
            return webhookUrl;
        }
        
        long timestamp = System.currentTimeMillis();
        String stringToSign = timestamp + "\n" + appSecret;
        
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(appSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] signData = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));
        String sign = URLEncoder.encode(Base64.getEncoder().encodeToString(signData), "UTF-8");
        
        String separator = webhookUrl.contains("?") ? "&" : "?";
        return webhookUrl + separator + "timestamp=" + timestamp + "&sign=" + sign;
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
            message.put("agent_id", agentId);
            
            if (useridList != null && !useridList.isEmpty()) {
                message.put("userid_list", useridList);
                message.put("dept_id_list", deptIdList);
            } else if (toAllUser) {
                message.put("to_all_user", true);
                if (deptIdList != null && !deptIdList.isEmpty()) {
                    message.put("dept_id_list", deptIdList);
                }
            }
            
            Map<String, Object> textContent = new HashMap<>();
            textContent.put("content", text);
            message.put("msg", createMsgMap("text", "text", textContent));

            return sendMessageViaAppApi(token, message);
        } catch (Exception e) {
            log.error("Failed to send text message via App API: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 通过应用API发送Markdown消息
     */
    private boolean sendMarkdownMessageViaAppApi(String title, String content) {
        try {
            String token = getAccessToken();
            if (token == null) {
                log.error("Failed to get access token");
                return false;
            }

            Map<String, Object> message = new HashMap<>();
            message.put("agent_id", agentId);
            
            if (useridList != null && !useridList.isEmpty()) {
                message.put("userid_list", useridList);
                message.put("dept_id_list", deptIdList);
            } else if (toAllUser) {
                message.put("to_all_user", true);
                if (deptIdList != null && !deptIdList.isEmpty()) {
                    message.put("dept_id_list", deptIdList);
                }
            }
            
            Map<String, Object> markdown = new HashMap<>();
            markdown.put("title", title);
            markdown.put("text", content);
            message.put("msg", createMsgMap("markdown", "markdown", markdown));

            return sendMessageViaAppApi(token, message);
        } catch (Exception e) {
            log.error("Failed to send markdown message via App API: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 创建消息Map
     */
    private Map<String, Object> createMsgMap(String msgType, String contentKey, Map<String, Object> content) {
        Map<String, Object> msg = new HashMap<>();
        msg.put("msgtype", msgType);
        msg.put(contentKey, content);
        return msg;
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
            String urlStr = TOKEN_API + "?appkey=" + appKey + "&appsecret=" + appSecret;
            log.info("Requesting access token from DingTalk API");
            
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
                
                log.debug("Token API response: {}", response.toString());
                
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
                log.error("Failed to get access token, status code: {}", statusCode);
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
            log.info("Sending message to DingTalk App API: {}", MESSAGE_API);
            
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            String jsonPayload = objectMapper.writeValueAsString(message);
            
            log.debug("Message payload: {}", jsonPayload);

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
                
                log.debug("Message API response: {}", response.toString());
                
                JsonNode root = objectMapper.readTree(response.toString());
                int errcode = root.has("errcode") ? root.get("errcode").asInt() : -1;

                if (errcode == 0) {
                    log.info("Message sent to DingTalk successfully via App API");
                    return true;
                } else {
                    log.error("Failed to send message to DingTalk App API, errcode: {}, errmsg: {}",
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
                log.error("Failed to send message to DingTalk App API, status: {}, error: {}", statusCode, errorResponse);
                return false;
            }
        } catch (Exception e) {
            log.error("Failed to send message to DingTalk App API: {}", e.getMessage(), e);
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
    private boolean sendToWebhook(String url, Map<String, Object> message) {
        HttpURLConnection conn = null;
        try {
            URL urlObj = new URL(url);
            conn = (HttpURLConnection) urlObj.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            String jsonPayload = objectMapper.writeValueAsString(message);
            
            log.debug("Sending message to DingTalk Webhook: {}", jsonPayload);

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
                    log.info("Message sent to DingTalk successfully via Webhook");
                    return true;
                } else {
                    log.error("Failed to send message to DingTalk Webhook, errcode: {}, errmsg: {}",
                            errcode, root.has("errmsg") ? root.get("errmsg").asText() : "unknown");
                    return false;
                }
            } else {
                log.error("Failed to send message to DingTalk Webhook, status code: {}", statusCode);
                return false;
            }
        } catch (Exception e) {
            log.error("Failed to send message to DingTalk Webhook: {}", e.getMessage(), e);
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
            log.warn("DingTalk notification not enabled");
            return false;
        }

        return sendTextMessage("🔍 钉钉机器人连接测试成功\n\n这是来自Input Security Starter的测试消息。");
    }

    /**
     * 遮蔽App Key
     */
    private String maskAppKey(String key) {
        if (key == null || key.length() < 8) {
            return key;
        }
        return key.substring(0, 4) + "****" + key.substring(key.length() - 4);
    }

    public boolean isEnabled() {
        return enabled && (useAppApi || (webhookUrl != null && !webhookUrl.isEmpty()));
    }

    public boolean isUseAppApi() {
        return useAppApi;
    }
}
