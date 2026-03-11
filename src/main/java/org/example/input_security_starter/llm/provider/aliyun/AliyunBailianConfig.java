package org.example.input_security_starter.llm.provider.aliyun;

import org.example.input_security_starter.llm.provider.LlmProviderConfig;

public class AliyunBailianConfig extends LlmProviderConfig {

    private static final String DEFAULT_API_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions";
    private static final String DEFAULT_MODEL = "qwen-plus";

    public AliyunBailianConfig() {
        this.apiUrl = DEFAULT_API_URL;
        this.model = DEFAULT_MODEL;
    }

    public AliyunBailianConfig(String apiUrl, String apiKey, String model) {
        this.apiUrl = (apiUrl != null && !apiUrl.trim().isEmpty()) ? apiUrl.trim() : DEFAULT_API_URL;
        this.apiKey = apiKey;
        this.model = (model != null && !model.trim().isEmpty()) ? model.trim() : DEFAULT_MODEL;
    }
}
