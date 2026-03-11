package org.example.input_security_starter.llm.provider.glm;

import org.example.input_security_starter.llm.provider.LlmProviderConfig;

public class GlmConfig extends LlmProviderConfig {

    private static final String DEFAULT_API_URL = "https://open.bigmodel.cn/api/paas/v4/chat/completions";
    private static final String DEFAULT_MODEL = "glm-4-flash";

    public GlmConfig() {
        this.apiUrl = DEFAULT_API_URL;
        this.model = DEFAULT_MODEL;
    }

    public GlmConfig(String apiUrl, String apiKey, String model) {
        this.apiUrl = (apiUrl != null && !apiUrl.trim().isEmpty()) ? apiUrl.trim() : DEFAULT_API_URL;
        this.apiKey = apiKey;
        this.model = (model != null && !model.trim().isEmpty()) ? model.trim() : DEFAULT_MODEL;
    }
}
