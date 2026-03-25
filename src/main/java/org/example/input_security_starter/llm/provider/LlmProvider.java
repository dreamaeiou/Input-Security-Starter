package org.example.input_security_starter.llm.provider;

import java.util.List;
import java.util.Map;

public interface LlmProvider {

    String getName();

    String analyze(String prompt);

    String analyzeAggregatedAlerts(String aggregatedJson);

    String analyzeAttackChain(List<String> alertLogs, Map<String, Object> ipIntelligence);

    boolean testConnection();

    boolean isAvailable();

    LlmProviderConfig getConfig();

    default String getLastFailureReason() {
        return null;
    }
}
