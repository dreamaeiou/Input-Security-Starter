package org.example.input_security_starter.llm.ip;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

public class IpQueryService {

    private static final Logger log = LoggerFactory.getLogger(IpQueryService.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final AbuseIpDbClient abuseIpDbClient;
    private final String ipLogDir;
    private final String indexFilePath;
    
    private final ConcurrentHashMap<String, IpIndexEntry> ipIndex;
    private final ExecutorService executorService;
    private final Set<String> pendingQueries;
    
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    private static final SimpleDateFormat DATETIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public IpQueryService(AbuseIpDbClient abuseIpDbClient, String ipLogDir) {
        this.abuseIpDbClient = abuseIpDbClient;
        this.ipLogDir = (ipLogDir != null && !ipLogDir.isEmpty()) ? ipLogDir : ".";
        this.indexFilePath = this.ipLogDir + File.separator + "ip_index.json";
        this.ipIndex = new ConcurrentHashMap<>();
        this.pendingQueries = ConcurrentHashMap.newKeySet();
        this.executorService = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ip-query-executor");
            t.setDaemon(true);
            return t;
        });
        
        loadIndex();
        
        log.info("IpQueryService initialized with logDir: {}", this.ipLogDir);
    }

    public void queryIpAsync(String ipAddress) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            return;
        }
        
        String today = DATE_FORMAT.format(new Date());
        String indexKey = ipAddress + "_" + today;
        
        if (ipIndex.containsKey(indexKey)) {
            log.debug("IP {} already queried today, skipping", ipAddress);
            return;
        }
        
        if (pendingQueries.contains(indexKey)) {
            log.debug("IP {} query already pending, skipping", ipAddress);
            return;
        }
        
        pendingQueries.add(indexKey);
        
        executorService.submit(() -> {
            try {
                queryAndSaveIp(ipAddress, today);
            } catch (Exception e) {
                log.error("Failed to query IP {}: {}", ipAddress, e.getMessage());
            } finally {
                pendingQueries.remove(indexKey);
            }
        });
    }

    private boolean queryAndSaveIp(String ipAddress, String dateStr) {
        if (abuseIpDbClient == null) {
            log.warn("AbuseIpDbClient not available, cannot query IP: {}", ipAddress);
            return false;
        }
        
        AbuseIpDbClient.IpIntelligence intelligence = abuseIpDbClient.checkIp(ipAddress);
        
        if (intelligence != null) {
            saveIpLog(ipAddress, dateStr, intelligence);
            updateIndex(ipAddress, dateStr, intelligence);
            return true;
        } else {
            updateIndexEmpty(ipAddress, dateStr);
            return false;
        }
    }

    private void saveIpLog(String ipAddress, String dateStr, AbuseIpDbClient.IpIntelligence intelligence) {
        String logFileName = "ip_" + dateStr + ".log";
        Path logPath = Paths.get(ipLogDir, logFileName);
        
        try {
            Files.createDirectories(Paths.get(ipLogDir));
            
            Map<String, Object> logEntry = new LinkedHashMap<>();
            logEntry.put("ip", ipAddress);
            logEntry.put("query_time", DATETIME_FORMAT.format(new Date()));
            logEntry.put("abuse_score", intelligence.getAbuseConfidenceScore());
            logEntry.put("total_reports", intelligence.getTotalReports());
            logEntry.put("distinct_users", intelligence.getNumDistinctUsers());
            logEntry.put("is_tor", intelligence.isTor());
            
            if (intelligence.getCountryCode() != null) {
                logEntry.put("country_code", intelligence.getCountryCode());
            }
            if (intelligence.getCountryName() != null) {
                logEntry.put("country_name", intelligence.getCountryName());
            }
            if (intelligence.getUsageType() != null) {
                logEntry.put("usage_type", intelligence.getUsageType());
            }
            if (intelligence.getIsp() != null) {
                logEntry.put("isp", intelligence.getIsp());
            }
            if (intelligence.getDomain() != null) {
                logEntry.put("domain", intelligence.getDomain());
            }
            if (intelligence.getHostnames() != null && !intelligence.getHostnames().isEmpty()) {
                logEntry.put("hostnames", intelligence.getHostnames());
            }
            if (intelligence.getLastReportedAt() != null) {
                logEntry.put("last_reported_at", intelligence.getLastReportedAt());
            }
            
            String jsonLine = objectMapper.writeValueAsString(logEntry);
            
            try (BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(new FileOutputStream(logPath.toFile(), true), StandardCharsets.UTF_8))) {
                writer.write(jsonLine);
                writer.newLine();
            }
            
            log.info("Saved IP log: {} -> {}", ipAddress, logFileName);
            
        } catch (Exception e) {
            log.error("Failed to save IP log for {}: {}", ipAddress, e.getMessage());
        }
    }

    private void updateIndex(String ipAddress, String dateStr, AbuseIpDbClient.IpIntelligence intelligence) {
        String indexKey = ipAddress + "_" + dateStr;
        
        IpIndexEntry entry = new IpIndexEntry();
        entry.setIpAddress(ipAddress);
        entry.setDate(dateStr);
        entry.setQueryTime(System.currentTimeMillis());
        entry.setAbuseScore(intelligence.getAbuseConfidenceScore());
        entry.setTotalReports(intelligence.getTotalReports());
        entry.setCountryCode(intelligence.getCountryCode());
        entry.setLogFileName("ip_" + dateStr + ".log");
        
        ipIndex.put(indexKey, entry);
        persistIndex();
        
        log.debug("Updated index for IP: {} on {}", ipAddress, dateStr);
    }

    private void updateIndexEmpty(String ipAddress, String dateStr) {
        String indexKey = ipAddress + "_" + dateStr;
        
        IpIndexEntry entry = new IpIndexEntry();
        entry.setIpAddress(ipAddress);
        entry.setDate(dateStr);
        entry.setQueryTime(System.currentTimeMillis());
        entry.setAbuseScore(-1);
        entry.setLogFileName("ip_" + dateStr + ".log");
        
        ipIndex.put(indexKey, entry);
        persistIndex();
        
        log.debug("Updated index (empty result) for IP: {} on {}", ipAddress, dateStr);
    }

    private void loadIndex() {
        Path indexPath = Paths.get(indexFilePath);
        
        if (!Files.exists(indexPath)) {
            log.info("IP index file not found, starting with empty index");
            return;
        }
        
        try {
            String content = new String(Files.readAllBytes(indexPath), StandardCharsets.UTF_8);
            if (content != null && !content.isEmpty()) {
                Map<String, Object> indexMap = objectMapper.readValue(content, Map.class);
                
                for (Map.Entry<String, Object> entry : indexMap.entrySet()) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> valueMap = (Map<String, Object>) entry.getValue();
                    IpIndexEntry indexEntry = new IpIndexEntry();
                    indexEntry.setIpAddress((String) valueMap.get("ip"));
                    indexEntry.setDate((String) valueMap.get("date"));
                    indexEntry.setQueryTime(valueMap.get("query_time") != null ? 
                            ((Number) valueMap.get("query_time")).longValue() : 0);
                    indexEntry.setAbuseScore(valueMap.get("abuse_score") != null ? 
                            ((Number) valueMap.get("abuse_score")).intValue() : -1);
                    indexEntry.setTotalReports(valueMap.get("total_reports") != null ? 
                            ((Number) valueMap.get("total_reports")).intValue() : 0);
                    indexEntry.setCountryCode((String) valueMap.get("country_code"));
                    indexEntry.setLogFileName((String) valueMap.get("log_file"));
                    
                    ipIndex.put(entry.getKey(), indexEntry);
                }
                
                log.info("Loaded {} IP index entries", ipIndex.size());
            }
            
        } catch (Exception e) {
            log.error("Failed to load IP index: {}", e.getMessage());
        }
    }

    private void persistIndex() {
        Path indexPath = Paths.get(indexFilePath);
        
        try {
            Files.createDirectories(Paths.get(ipLogDir));
            
            Map<String, Object> indexMap = new LinkedHashMap<>();
            for (Map.Entry<String, IpIndexEntry> entry : ipIndex.entrySet()) {
                indexMap.put(entry.getKey(), entry.getValue().toMap());
            }
            
            String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(indexMap);
            
            try (BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(new FileOutputStream(indexPath.toFile()), StandardCharsets.UTF_8))) {
                writer.write(json);
            }
            
        } catch (Exception e) {
            log.error("Failed to persist IP index: {}", e.getMessage());
        }
    }

    public IpIndexEntry queryIndex(String ipAddress, String dateStr) {
        String indexKey = ipAddress + "_" + dateStr;
        return ipIndex.get(indexKey);
    }

    public IpIndexEntry queryIndexToday(String ipAddress) {
        String today = DATE_FORMAT.format(new Date());
        return queryIndex(ipAddress, today);
    }

    public List<IpIndexEntry> queryIndexByIp(String ipAddress) {
        List<IpIndexEntry> results = new ArrayList<>();
        
        for (Map.Entry<String, IpIndexEntry> entry : ipIndex.entrySet()) {
            if (entry.getKey().startsWith(ipAddress + "_")) {
                results.add(entry.getValue());
            }
        }
        
        results.sort((a, b) -> Long.compare(b.getQueryTime(), a.getQueryTime()));
        return results;
    }

    public List<IpIndexEntry> queryIndexByDate(String dateStr) {
        List<IpIndexEntry> results = new ArrayList<>();
        
        for (Map.Entry<String, IpIndexEntry> entry : ipIndex.entrySet()) {
            if (entry.getKey().endsWith("_" + dateStr)) {
                results.add(entry.getValue());
            }
        }
        
        results.sort((a, b) -> Long.compare(b.getQueryTime(), a.getQueryTime()));
        return results;
    }

    public List<IpIndexEntry> getAllIndexEntries() {
        return new ArrayList<>(ipIndex.values());
    }

    public int getIndexSize() {
        return ipIndex.size();
    }

    public Set<String> getCachedIps(Set<String> ips) {
        Set<String> cached = new HashSet<>();
        String today = DATE_FORMAT.format(new Date());
        
        for (String ip : ips) {
            if (ip == null || ip.isEmpty()) continue;
            IpIndexEntry entry = queryIndex(ip, today);
            if (entry != null && entry.getAbuseScore() >= 0) {
                cached.add(ip);
            }
        }
        
        return cached;
    }

    public Map<String, AbuseIpDbClient.IpIntelligence> getIpIntelligenceForAnalysis(Set<String> ips) {
        Map<String, AbuseIpDbClient.IpIntelligence> result = new HashMap<>();
        String today = DATE_FORMAT.format(new Date());
        
        for (String ip : ips) {
            if (ip == null || ip.isEmpty()) continue;
            
            IpIndexEntry indexEntry = queryIndex(ip, today);
            if (indexEntry != null && indexEntry.getAbuseScore() >= 0) {
                AbuseIpDbClient.IpIntelligence intel = readIpIntelligenceFromLog(ip, indexEntry.getLogFileName());
                if (intel != null) {
                    result.put(ip, intel);
                    log.debug("Loaded cached IP intelligence for: {}", ip);
                    continue;
                }
            }
            
            if (abuseIpDbClient != null) {
                AbuseIpDbClient.IpIntelligence intel = queryIpSync(ip, today);
                if (intel != null) {
                    result.put(ip, intel);
                }
            }
        }
        
        log.info("Retrieved IP intelligence for {} out of {} IPs", result.size(), ips.size());
        
        return result;
    }

    private AbuseIpDbClient.IpIntelligence queryIpSync(String ipAddress, String dateStr) {
        try {
            AbuseIpDbClient.IpIntelligence intel = abuseIpDbClient.checkIp(ipAddress);
            if (intel != null) {
                saveIpLog(ipAddress, dateStr, intel);
                updateIndex(ipAddress, dateStr, intel);
                return intel;
            }
        } catch (Exception e) {
            log.error("Failed to query IP {}: {}", ipAddress, e.getMessage());
        }
        return null;
    }

    private AbuseIpDbClient.IpIntelligence readIpIntelligenceFromLog(String ipAddress, String logFileName) {
        Path logPath = Paths.get(ipLogDir, logFileName);
        
        if (!Files.exists(logPath)) {
            return null;
        }
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(logPath.toFile()), StandardCharsets.UTF_8))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                
                try {
                    Map<String, Object> entry = objectMapper.readValue(line, Map.class);
                    String entryIp = (String) entry.get("ip");
                    
                    if (ipAddress.equals(entryIp)) {
                        AbuseIpDbClient.IpIntelligence intel = new AbuseIpDbClient.IpIntelligence();
                        intel.setIpAddress(ipAddress);
                        intel.setFetchedAt(System.currentTimeMillis());
                        intel.setAbuseConfidenceScore(getIntValue(entry, "abuse_score"));
                        intel.setTotalReports(getIntValue(entry, "total_reports"));
                        intel.setNumDistinctUsers(getIntValue(entry, "distinct_users"));
                        intel.setTor(getBoolValue(entry, "is_tor"));
                        intel.setCountryCode((String) entry.get("country_code"));
                        intel.setCountryName((String) entry.get("country_name"));
                        intel.setUsageType((String) entry.get("usage_type"));
                        intel.setIsp((String) entry.get("isp"));
                        intel.setDomain((String) entry.get("domain"));
                        intel.setLastReportedAt((String) entry.get("last_reported_at"));
                        
                        Object hostnames = entry.get("hostnames");
                        if (hostnames instanceof List) {
                            @SuppressWarnings("unchecked")
                            List<String> hostnameList = (List<String>) hostnames;
                            intel.setHostnames(hostnameList);
                        }
                        
                        return intel;
                    }
                } catch (Exception e) {
                    log.debug("Failed to parse IP log line: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Failed to read IP log file {}: {}", logFileName, e.getMessage());
        }
        
        return null;
    }

    private int getIntValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return 0;
    }

    private boolean getBoolValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return false;
    }

    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        persistIndex();
        log.info("IpQueryService shutdown complete");
    }

    public static class IpIndexEntry {
        private String ipAddress;
        private String date;
        private long queryTime;
        private int abuseScore;
        private int totalReports;
        private String countryCode;
        private String logFileName;

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("ip", ipAddress);
            map.put("date", date);
            map.put("query_time", queryTime);
            map.put("abuse_score", abuseScore);
            map.put("total_reports", totalReports);
            map.put("country_code", countryCode);
            map.put("log_file", logFileName);
            return map;
        }

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public String getDate() { return date; }
        public void setDate(String date) { this.date = date; }
        public long getQueryTime() { return queryTime; }
        public void setQueryTime(long queryTime) { this.queryTime = queryTime; }
        public int getAbuseScore() { return abuseScore; }
        public void setAbuseScore(int abuseScore) { this.abuseScore = abuseScore; }
        public int getTotalReports() { return totalReports; }
        public void setTotalReports(int totalReports) { this.totalReports = totalReports; }
        public String getCountryCode() { return countryCode; }
        public void setCountryCode(String countryCode) { this.countryCode = countryCode; }
        public String getLogFileName() { return logFileName; }
        public void setLogFileName(String logFileName) { this.logFileName = logFileName; }
    }
}
