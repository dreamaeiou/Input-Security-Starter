package org.example.input_security_starter.llm.schedule;

public class AlertProcessingState {

    private long lastProcessedLine;
    private long lastProcessedAt;
    private String lastReportId;

    public long getLastProcessedLine() {
        return lastProcessedLine;
    }

    public void setLastProcessedLine(long lastProcessedLine) {
        this.lastProcessedLine = lastProcessedLine;
    }

    public long getLastProcessedAt() {
        return lastProcessedAt;
    }

    public void setLastProcessedAt(long lastProcessedAt) {
        this.lastProcessedAt = lastProcessedAt;
    }

    public String getLastReportId() {
        return lastReportId;
    }

    public void setLastReportId(String lastReportId) {
        this.lastReportId = lastReportId;
    }
}
