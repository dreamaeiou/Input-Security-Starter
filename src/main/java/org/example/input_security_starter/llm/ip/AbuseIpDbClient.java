package org.example.input_security_starter.llm.ip;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AbuseIpDbClient {

    private static final Logger log = LoggerFactory.getLogger(AbuseIpDbClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final String apiUrl;
    private final String apiKey;
    private final int maxAgeDays;
    
    private final ConcurrentHashMap<String, IpIntelligence> intelligenceCache;
    private static final long CACHE_TTL_MS = 3600 * 1000;

    public AbuseIpDbClient(String apiUrl, String apiKey, int maxAgeDays) {
        this.apiUrl = (apiUrl != null && !apiUrl.isEmpty()) ? apiUrl : "https://api.abuseipdb.com/api/v2/check";
        this.apiKey = apiKey;
        this.maxAgeDays = maxAgeDays;
        this.intelligenceCache = new ConcurrentHashMap<>();
        
        log.info("AbuseIpDbClient initialized with maxAgeDays: {}", maxAgeDays);
    }

    public IpIntelligence checkIp(String ipAddress) {
        if (apiKey == null || apiKey.isEmpty()) {
            log.warn("AbuseIPDB API key not configured, skipping IP intelligence check");
            return null;
        }
        
        if (ipAddress == null || ipAddress.isEmpty()) {
            return null;
        }
        
        IpIntelligence cached = intelligenceCache.get(ipAddress);
        if (cached != null && !cached.isExpired()) {
            log.debug("Using cached intelligence for IP: {}", ipAddress);
            return cached;
        }
        
        try {
            String response = sendRequest(ipAddress);
            if (response != null) {
                IpIntelligence intelligence = parseResponse(response, ipAddress);
                if (intelligence != null) {
                    intelligenceCache.put(ipAddress, intelligence);
                    return intelligence;
                }
            }
        } catch (Exception e) {
            log.error("Failed to check IP intelligence for {}: {}", ipAddress, e.getMessage());
        }
        
        return null;
    }

    public Map<String, IpIntelligence> checkIps(List<String> ipAddresses) {
        Map<String, IpIntelligence> result = new HashMap<>();
        
        if (ipAddresses == null || ipAddresses.isEmpty()) {
            return result;
        }
        
        List<String> uniqueIps = new ArrayList<>(new java.util.HashSet<>(ipAddresses));
        
        for (String ip : uniqueIps) {
            IpIntelligence intelligence = checkIp(ip);
            if (intelligence != null) {
                result.put(ip, intelligence);
            }
            
            try {
                Thread.sleep(250);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return result;
    }

    private String sendRequest(String ipAddress) {
        HttpURLConnection conn = null;
        try {
            String urlStr = apiUrl + "?ipAddress=" + URLEncoder.encode(ipAddress, StandardCharsets.UTF_8.name())
                    + "&maxAgeInDays=" + maxAgeDays;
            
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Key", apiKey);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(15000);
            
            int statusCode = conn.getResponseCode();
            
            if (statusCode == 200) {
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder response = new StringBuilder();
                    String responseLine;
                    while ((responseLine = br.readLine()) != null) {
                        response.append(responseLine.trim());
                    }
                    log.debug("AbuseIPDB response for {}: {} bytes", ipAddress, response.length());
                    return response.toString();
                }
            } else if (statusCode == 429) {
                log.warn("AbuseIPDB API rate limit exceeded for IP: {}", ipAddress);
                String retryAfter = conn.getHeaderField("Retry-After");
                if (retryAfter != null) {
                    log.warn("Retry after: {} seconds", retryAfter);
                }
            } else {
                String errorBody = readErrorStream(conn);
                log.error("AbuseIPDB API error for IP {}: status={}, error={}", ipAddress, statusCode, errorBody);
            }
        } catch (java.net.SocketTimeoutException e) {
            log.error("AbuseIPDB API timeout for IP {}: {}", ipAddress, e.getMessage());
        } catch (java.net.UnknownHostException e) {
            log.error("AbuseIPDB API unknown host: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Failed to send request to AbuseIPDB API for IP {}: {}", ipAddress, e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return null;
    }

    private String readErrorStream(HttpURLConnection conn) {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            return response.toString();
        } catch (Exception e) {
            return "Unable to read error stream: " + e.getMessage();
        }
    }

    private IpIntelligence parseResponse(String jsonResponse, String ipAddress) {
        try {
            JsonNode root = objectMapper.readTree(jsonResponse);
            
            if (!root.has("data")) {
                log.warn("AbuseIPDB response missing 'data' field");
                return null;
            }
            
            JsonNode data = root.get("data");
            
            IpIntelligence intelligence = new IpIntelligence();
            intelligence.setIpAddress(ipAddress);
            intelligence.setFetchedAt(System.currentTimeMillis());
            
            if (data.has("abuseConfidenceScore")) {
                intelligence.setAbuseConfidenceScore(data.get("abuseConfidenceScore").asInt());
            }
            
            if (data.has("totalReports")) {
                intelligence.setTotalReports(data.get("totalReports").asInt());
            }
            
            if (data.has("numDistinctUsers")) {
                intelligence.setNumDistinctUsers(data.get("numDistinctUsers").asInt());
            }
            
            if (data.has("isTor")) {
                intelligence.setTor(data.get("isTor").asBoolean());
            }
            
            if (data.has("countryCode")) {
                intelligence.setCountryCode(data.get("countryCode").asText());
            }
            
            if (data.has("countryName")) {
                intelligence.setCountryName(data.get("countryName").asText());
            }
            
            if (data.has("usageType")) {
                intelligence.setUsageType(data.get("usageType").asText());
            }
            
            if (data.has("isp")) {
                intelligence.setIsp(data.get("isp").asText());
            }
            
            if (data.has("domain")) {
                intelligence.setDomain(data.get("domain").asText());
            }
            
            if (data.has("hostnames") && data.get("hostnames").isArray()) {
                List<String> hostnames = new ArrayList<>();
                for (JsonNode hostname : data.get("hostnames")) {
                    hostnames.add(hostname.asText());
                }
                intelligence.setHostnames(hostnames);
            }
            
            if (data.has("lastReportedAt")) {
                intelligence.setLastReportedAt(data.get("lastReportedAt").asText());
            }
            
            return intelligence;
            
        } catch (Exception e) {
            log.error("Failed to parse AbuseIPDB response: {}", e.getMessage());
            return null;
        }
    }

    public void cleanExpiredCache() {
        long now = System.currentTimeMillis();
        intelligenceCache.entrySet().removeIf(entry -> 
            entry.getValue() == null || entry.getValue().isExpired());
    }

    public static class IpIntelligence {
        private String ipAddress;
        private long fetchedAt;
        private int abuseConfidenceScore;
        private int totalReports;
        private int numDistinctUsers;
        private boolean isTor;
        private String countryCode;
        private String countryName;
        private String usageType;
        private String isp;
        private String domain;
        private List<String> hostnames;
        private String lastReportedAt;

        public boolean isExpired() {
            return System.currentTimeMillis() - fetchedAt > CACHE_TTL_MS;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new HashMap<>();
            result.put("ip", ipAddress);
            result.put("abuse_score", abuseConfidenceScore);
            result.put("reports", totalReports);
            result.put("distinct_users", numDistinctUsers);
            result.put("is_tor", isTor);
            if (countryCode != null) {
                result.put("country", countryCode);
            }
            if (usageType != null) {
                result.put("usage_type", usageType);
            }
            if (isp != null) {
                result.put("isp", isp);
            }
            if (lastReportedAt != null) {
                result.put("last_report", lastReportedAt);
            }
            return result;
        }

        public String toSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("IP: ").append(ipAddress);
            sb.append(", Abuse Score: ").append(abuseConfidenceScore);
            sb.append(", Reports: ").append(totalReports);
            if (isTor) {
                sb.append(", TOR Exit Node");
            }
            if (countryCode != null) {
                sb.append(", Country: ").append(countryCode);
            }
            if (usageType != null) {
                sb.append(", Type: ").append(usageType);
            }
            return sb.toString();
        }

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public long getFetchedAt() { return fetchedAt; }
        public void setFetchedAt(long fetchedAt) { this.fetchedAt = fetchedAt; }
        public int getAbuseConfidenceScore() { return abuseConfidenceScore; }
        public void setAbuseConfidenceScore(int abuseConfidenceScore) { this.abuseConfidenceScore = abuseConfidenceScore; }
        public int getTotalReports() { return totalReports; }
        public void setTotalReports(int totalReports) { this.totalReports = totalReports; }
        public int getNumDistinctUsers() { return numDistinctUsers; }
        public void setNumDistinctUsers(int numDistinctUsers) { this.numDistinctUsers = numDistinctUsers; }
        public boolean isTor() { return isTor; }
        public void setTor(boolean tor) { isTor = tor; }
        public String getCountryCode() { return countryCode; }
        public void setCountryCode(String countryCode) { this.countryCode = countryCode; }
        public String getCountryName() { return countryName; }
        public void setCountryName(String countryName) { this.countryName = countryName; }
        public String getUsageType() { return usageType; }
        public void setUsageType(String usageType) { this.usageType = usageType; }
        public String getIsp() { return isp; }
        public void setIsp(String isp) { this.isp = isp; }
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        public List<String> getHostnames() { return hostnames; }
        public void setHostnames(List<String> hostnames) { this.hostnames = hostnames; }
        public String getLastReportedAt() { return lastReportedAt; }
        public void setLastReportedAt(String lastReportedAt) { this.lastReportedAt = lastReportedAt; }
    }
}
