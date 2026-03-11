package org.example.input_security_starter.event;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.tracker.AttackChainTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PreDestroy;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 安全事件记录器
 * 负责记录和管理安全事件，支持：
 * 1. 内存存储最近事件（最多 100,000 条）
 * 2. 异步日志文件写入
 * 3. 日志文件轮转和大小限制
 * 4. 路径遍历防护
 * 
 * 日志格式：JSON Lines，便于 LLM/AI 分析
 */
public class EventRecorder {

    private static final Logger log = LoggerFactory.getLogger(EventRecorder.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /** 内存中存储的安全事件队列（使用 Deque 实现 O(1) 头部删除） */
    private final Deque<SecurityEvent> events = new ArrayDeque<>();
    /** 内存存储锁，保证线程安全 */
    private final ReentrantLock memoryLock = new ReentrantLock();
    /** 内存存储最大事件数 */
    private static final int MAX_EVENTS = 100000;

    /** 异步日志写入队列 */
    private final BlockingQueue<String> logQueue = new LinkedBlockingQueue<>(10000);
    /** 异步日志写入线程 */
    private final Thread logWriterThread;
    /** 运行状态标志 */
    private volatile boolean running = true;
    /** 日志文件路径 */
    private final String logFilePath;
    /** 日志文件最大大小（字节） */
    private final long maxLogSize;
    /** 日志文件最大数量 */
    private final int maxLogFiles;
    /** 当前日志日期（用于按日期分割日志） */
    private String currentLogDate = "";
    
    /** 攻击链追踪器（可选） */
    private AttackChainTracker attackChainTracker;

    /**
     * 默认构造函数
     * 使用默认配置初始化
     */
    public EventRecorder() {
        this("security-events.log", 50, 10, true);
    }
    
    /**
     * 构造函数
     * @param logFilePath 日志文件路径
     * @param maxLogSizeMb 日志文件最大大小（MB）
     * @param maxLogFiles 日志文件最大数量
     */
    public EventRecorder(String logFilePath, int maxLogSizeMb, int maxLogFiles) {
        this(logFilePath, maxLogSizeMb, maxLogFiles, true);
    }
    
    /**
     * 完整构造函数
     * @param logFilePath 日志文件路径
     * @param maxLogSizeMb 日志文件最大大小（MB）
     * @param maxLogFiles 日志文件最大数量
     * @param asyncLogEnabled 是否启用异步日志
     */
    public EventRecorder(String logFilePath, int maxLogSizeMb, int maxLogFiles, boolean asyncLogEnabled) {
        this.logFilePath = validateLogFilePath(logFilePath);
        this.maxLogSize = maxLogSizeMb * 1024L * 1024L;
        this.maxLogFiles = maxLogFiles;
        this.currentLogDate = getCurrentDateString();
        
        if (asyncLogEnabled) {
            logWriterThread = new Thread(this::asyncLogWriter, "security-event-writer");
            logWriterThread.setDaemon(true);
            logWriterThread.start();
            log.info("EventRecorder initialized: path={}, maxSize={}MB, maxFiles={}", 
                     this.logFilePath, maxLogSizeMb, maxLogFiles);
        } else {
            logWriterThread = null;
        }
    }
    
    /**
     * 验证日志文件路径安全性
     * 防止路径遍历攻击和敏感目录写入
     * @param path 日志文件路径
     * @return 验证后的路径
     * @throws SecurityException 如果路径不安全
     */
    private String validateLogFilePath(String path) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("Log file path cannot be null or empty");
        }
        
        String normalizedPath = path.trim();
        
        // 检查路径遍历
        if (normalizedPath.contains("..")) {
            throw new SecurityException("Path traversal detected in log file path: " + path);
        }
        
        // 检查是否为绝对路径，如果是则验证是否为敏感目录
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
        
        // 检查文件扩展名
        String fileName = new File(normalizedPath).getName();
        if (!fileName.endsWith(".log") && !fileName.endsWith(".json")) {
            log.warn("Log file path does not have standard extension (.log/.json): {}", path);
        }
        
        return normalizedPath;
    }
    
    /**
     * 获取当前日期字符串
     * @return 格式化的日期字符串（yyyy-MM-dd）
     */
    private String getCurrentDateString() {
        return new SimpleDateFormat("yyyy-MM-dd").format(new Date());
    }

    /**
     * 记录安全事件
     * 同时存储到内存、写入日志文件、通知攻击链追踪器
     * @param event 安全事件
     */
    public void record(SecurityEvent event) {
        addToMemory(event);
        writeLog(event);
        
        // 通知攻击链追踪器（异步，低开销）
        if (attackChainTracker != null) {
            attackChainTracker.onSecurityEvent(event);
        }
    }
    
    /**
     * 设置攻击链追踪器
     * @param tracker 攻击链追踪器
     */
    public void setAttackChainTracker(AttackChainTracker tracker) {
        this.attackChainTracker = tracker;
    }

    /**
     * 获取最近的安全事件
     * @param limit 返回数量限制
     * @return 安全事件列表
     */
    public List<SecurityEvent> getRecentEvents(int limit) {
        memoryLock.lock();
        try {
            List<SecurityEvent> result = new ArrayList<>();
            int skipCount = Math.max(0, events.size() - limit);
            int index = 0;
            for (SecurityEvent event : events) {
                if (index >= skipCount) {
                    result.add(event);
                }
                index++;
            }
            return result;
        } finally {
            memoryLock.unlock();
        }
    }

    /**
     * 获取攻击类型统计（按规则名称分组）
     * @return 规则名称到数量的映射
     */
    public Map<String, Integer> getAttackTypeStats() {
        memoryLock.lock();
        try {
            Map<String, Integer> stats = new HashMap<>();
            for (SecurityEvent event : events) {
                String rule = event.getRuleName();
                stats.put(rule, stats.getOrDefault(rule, 0) + 1);
            }
            return stats;
        } finally {
            memoryLock.unlock();
        }
    }

    /**
     * 获取按时间分组的攻击统计（按小时）
     * @param lastNHours 最近N小时
     * @return 时间戳（小时）到数量的映射
     */
    public Map<Long, Integer> getAttackTrendByHour(int lastNHours) {
        memoryLock.lock();
        try {
            Map<Long, Integer> trend = new HashMap<>();
            long currentHour = System.currentTimeMillis() / (1000 * 60 * 60);
            long cutoffHour = currentHour - lastNHours;
            
            for (SecurityEvent event : events) {
                long eventHour = event.getTimestamp().getTime() / (1000 * 60 * 60);
                if (eventHour >= cutoffHour) {
                    trend.put(eventHour, trend.getOrDefault(eventHour, 0) + 1);
                }
            }
            return trend;
        } finally {
            memoryLock.unlock();
        }
    }

    /**
     * 获取攻击类型随时间变化的统计（用于ECharts）
     * @param lastNHours 最近N小时
     * @return 包含时间和各攻击类型数量的数据结构
     */
    public Map<String, Object> getAttackTrendWithTypes(int lastNHours) {
        memoryLock.lock();
        try {
            Map<Long, Map<String, Integer>> timeTypeMap = new HashMap<>();
            long currentHour = System.currentTimeMillis() / (1000 * 60 * 60);
            long cutoffHour = currentHour - lastNHours;
            
            // 收集所有规则类型
            java.util.Set<String> allRules = new java.util.HashSet<>();
            
            for (SecurityEvent event : events) {
                long eventHour = event.getTimestamp().getTime() / (1000 * 60 * 60);
                if (eventHour >= cutoffHour) {
                    String rule = event.getRuleName();
                    allRules.add(rule);
                    
                    timeTypeMap.computeIfAbsent(eventHour, k -> new HashMap<>())
                               .put(rule, timeTypeMap.get(eventHour).getOrDefault(rule, 0) + 1);
                }
            }
            
            // 构建返回数据结构
            Map<String, Object> result = new HashMap<>();
            result.put("rules", new ArrayList<>(allRules));
            result.put("timeData", timeTypeMap);
            return result;
        } finally {
            memoryLock.unlock();
        }
    }

    /**
     * 获取待写入的日志队列大小
     * @return 队列大小
     */
    public int getPendingCount() {
        return logQueue.size();
    }

    /**
     * 将事件添加到内存存储
     * 超过最大数量时移除最旧的事件
     * @param event 安全事件
     */
    private void addToMemory(SecurityEvent event) {
        memoryLock.lock();
        try {
            events.addLast(event);
            while (events.size() > MAX_EVENTS) {
                events.pollFirst();
            }
        } finally {
            memoryLock.unlock();
        }
    }

    /**
     * 异步日志写入线程主循环
     * 批量从队列取出日志并写入文件
     */
    private void asyncLogWriter() {
        while (running || !logQueue.isEmpty()) {
            try {
                List<String> batch = new ArrayList<>();
                String first = logQueue.poll(1, TimeUnit.SECONDS);
                if (first != null) {
                    batch.add(first);
                    logQueue.drainTo(batch, 99);
                }
                
                if (!batch.isEmpty()) {
                    writeBatchToFile(batch);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error in log writer thread", e);
            }
        }
    }

    /**
     * 批量写入日志到文件
     * 支持日志轮转和按日期分割
     * @param batch 日志行列表
     */
    private void writeBatchToFile(List<String> batch) {
        try {
            String today = getCurrentDateString();
            if (!today.equals(currentLogDate)) {
                currentLogDate = today;
            }
            
            String logFileName = getLogFileName();
            File logFile = new File(logFileName);
            
            // 检查日志文件大小，超过限制则轮转
            if (logFile.exists() && logFile.length() > maxLogSize) {
                rotateLogFile(logFileName);
            }
            
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFileName, true))) {
                for (String entry : batch) {
                    writer.write(entry);
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            log.error("Failed to write security events: {}", e.getMessage());
        }
    }
    
    /**
     * 获取带日期的日志文件名
     * @return 日志文件名
     */
    private String getLogFileName() {
        if (logFilePath.contains(".")) {
            int dotIndex = logFilePath.lastIndexOf(".");
            return logFilePath.substring(0, dotIndex) + "-" + currentLogDate + logFilePath.substring(dotIndex);
        }
        return logFilePath + "-" + currentLogDate + ".log";
    }
    
    /**
     * 轮转日志文件
     * 将旧日志文件重命名为 .1, .2, ... 格式
     * @param currentFile 当前日志文件路径
     */
    private void rotateLogFile(String currentFile) {
        try {
            File oldFile = new File(currentFile);
            String baseName = currentFile.replace(".log", "");
            
            // 删除最旧的日志文件
            File oldestFile = new File(baseName + "." + maxLogFiles + ".log");
            if (oldestFile.exists()) {
                oldestFile.delete();
            }
            
            // 重命名现有日志文件
            for (int i = maxLogFiles - 1; i >= 1; i--) {
                File existingFile = new File(baseName + "." + i + ".log");
                if (existingFile.exists()) {
                    File newFile = new File(baseName + "." + (i + 1) + ".log");
                    existingFile.renameTo(newFile);
                }
            }
            
            // 将当前日志文件重命名为 .1
            File rotated = new File(baseName + ".1.log");
            oldFile.renameTo(rotated);
            log.info("Rotated log file: {} -> {}", currentFile, rotated.getName());
        } catch (Exception e) {
            log.error("Failed to rotate log file: {}", e.getMessage());
        }
    }

    /**
     * 将日志行加入异步写入队列或直接写入文件
     * @param logLine 日志行
     */
    private void writeLogToFile(String logLine) {
        if (logWriterThread != null) {
            // 异步模式：加入队列
            try {
                logQueue.put(logLine);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Failed to queue log line", e);
            }
        } else {
            // 同步模式：直接写入文件
            try {
                writeBatchToFile(java.util.Collections.singletonList(logLine));
            } catch (Exception e) {
                log.error("Failed to write log line: {}", e.getMessage());
            }
        }
    }
    
    /**
     * 将安全事件写入日志
     * 优先使用 JSON 格式，失败时使用简化格式
     * @param event 安全事件
     */
    private void writeLog(SecurityEvent event) {
        try {
            String jsonLine = objectMapper.writeValueAsString(event.toMap());
            writeLogToFile(jsonLine);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize event: {}", e.getMessage());
            writeFallbackLog(event);
        }
    }
    
    /**
     * 备用日志写入方法
     * 当 JSON 序列化失败时使用简化格式
     * @param event 安全事件
     */
    private void writeFallbackLog(SecurityEvent event) {
        StringBuilder fallbackLog = new StringBuilder();
        fallbackLog.append("{\"ts\":").append(event.getTimestamp().getTime());
        fallbackLog.append(",\"rule\":\"").append(event.getRuleName()).append("\"");
        fallbackLog.append(",\"ip\":\"").append(event.getIpAddress() != null ? event.getIpAddress() : "").append("\"");
        fallbackLog.append(",\"url\":\"").append(escapeJson(event.getUrl())).append("\"}");
        writeLogToFile(fallbackLog.toString());
    }
    
    /**
     * JSON 字符串转义
     * @param str 原始字符串
     * @return 转义后的字符串
     */
    private String escapeJson(String str) {
        if (str == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * 关闭事件记录器
     * 刷新待写入的日志并停止异步写入线程
     */
    @PreDestroy
    public void shutdown() {
        log.info("Shutting down EventRecorder, flushing {} pending events", logQueue.size());
        running = false;
        
        try {
            if (logWriterThread != null) {
                logWriterThread.join(5000);
            }
            
            // 刷新剩余日志
            if (!logQueue.isEmpty()) {
                List<String> remaining = new ArrayList<>();
                logQueue.drainTo(remaining);
                if (!remaining.isEmpty()) {
                    writeBatchToFile(remaining);
                    log.info("Flushed {} remaining events", remaining.size());
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Interrupted while waiting for log writer to finish");
        }
    }
}
