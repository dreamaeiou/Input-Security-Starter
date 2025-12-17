package org.example.input_security_starter.event;

import org.springframework.stereotype.Component;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

@Component
public class EventRecorder {

    private final List<SecurityEvent> events = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();
    private static final int MAX_EVENTS = 100000;
    private static final String LOG_FILE_PATH = "security-events.log";

    public void record(SecurityEvent event) {
        lock.lock();
        try {
            // 添加到内存列表用于UI展示
            events.add(event);
            
            // 保持最近的事件，避免内存溢出
            if (events.size() > MAX_EVENTS) {
                events.remove(0);
            }
            
            // 记录到文本文件
            writeToLogFile(event);
        } finally {
            lock.unlock();
        }
    }

    public List<SecurityEvent> getRecentEvents(int limit) {
        lock.lock();
        try {
            int from = Math.max(0, events.size() - limit);
            return new ArrayList<>(events.subList(from, events.size()));
        } finally {
            lock.unlock();
        }
    }
    
    private void writeToLogFile(SecurityEvent event) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE_PATH, true))) {
            String logEntry = String.format("%s | %s | %s | %s | %s%n",
                    event.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                    event.getIpAddress() != null ? event.getIpAddress() : "UNKNOWN",
                    event.getRuleName(),
                    event.getMethod(),
                    event.getInputSnippet());
            writer.write(logEntry);
        } catch (IOException e) {
            // 静默处理文件写入错误，避免影响主流程
            System.err.println("Failed to write security event to log file: " + e.getMessage());
        }
    }
}