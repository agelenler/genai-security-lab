package com.genai.security.config;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.SimpleLoggerAdvisor;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.retry.RetryPolicy;
import org.springframework.core.retry.RetryTemplate;

/**
 * Spring ChatClient configurations
 */
@Configuration
public class AIProviderConfig {
    @Bean("ollamaChatClient")
    public ChatClient ollamaChatClient(OllamaChatModel ollamaChatModel) {
        return ChatClient.builder(ollamaChatModel)
                .defaultAdvisors(new SimpleLoggerAdvisor())
                .build();
    }

    @Bean
    public RetryTemplate retryTemplate() {
        // Do not automatically retry failed model requests.
        return new RetryTemplate(RetryPolicy.builder().maxRetries(0).build());
    }
}
