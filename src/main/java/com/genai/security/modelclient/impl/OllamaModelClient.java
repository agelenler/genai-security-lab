package com.genai.security.modelclient.impl;

import com.genai.security.dto.Message;
import com.genai.security.modelclient.ModelClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.concurrent.Semaphore;

@Component
public class OllamaModelClient implements ModelClient {
    private final ChatClient chatClient;
    private final Semaphore slots = new Semaphore(2);

    private static final Logger log = LoggerFactory.getLogger(OllamaModelClient.class);

    public OllamaModelClient(@Qualifier("ollamaChatClient") ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @Override
    public String chat(List<Message> messages, boolean json) {
        return execute(messages, json, null, null, null, null);
    }

    @Override
    public String chatWithTools(List<Message> messages, Object tools, String model) {
        return execute(messages, false, tools, model, null, null);
    }

    @Override
    public String chatWithImage(List<Message> messages, Object tools, String model,
                                org.springframework.core.io.Resource image, org.springframework.util.MimeType mimeType) {
        return execute(messages, false, tools, model, image, mimeType);
    }

    private String execute(List<Message> messages, boolean json, Object tools, String model,
                           org.springframework.core.io.Resource image, org.springframework.util.MimeType mimeType) {
        if (!slots.tryAcquire()) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Two model calls already running");
        }

        try {
            // Preserve actual roles and raw text. JSON braces in attack text are not template variables.
            List<org.springframework.ai.chat.messages.Message> springMessages = messages.stream()
                    .map(m -> image != null && m.role().equals("user")
                            ? (org.springframework.ai.chat.messages.Message) UserMessage.builder()
                            .text(m.content()).media(new org.springframework.ai.content.Media(mimeType, image)).build()
                            : toSpringMessage(m)).toList();

            var request = chatClient.prompt().messages(springMessages);

            // Per-call JSON mode must not affect later plain-text experiments.
            if (json) {
                request.options(OllamaChatOptions.builder().format("json"));
            }

            if (model != null) {
                request.options(OllamaChatOptions.builder().model(model));
            }

            if (tools != null) {
                request.tools(tools);
            }

            String output = request.call().content();
            if (output == null || output.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Model returned no text content");
            }

            return output;
        } catch (ResponseStatusException error) {
            log.warn("Model request failed: {}", error.getReason(), error);
            throw error;
        } catch (RuntimeException error) {
            log.error("Spring AI / Ollama request failed", error);
            // No provider error bodies, prompts or credentials in the response.
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Spring AI / Ollama request failed. Start Ollama, check the installed model, and check the URL/timeouts.");
        } finally {
            slots.release();
        }
    }

    private org.springframework.ai.chat.messages.Message toSpringMessage(Message message) {
        return switch (message.role()) {
            case "system" -> new SystemMessage(message.content());
            case "user" -> new UserMessage(message.content());
            default -> throw new IllegalArgumentException("Unsupported role in this two-message lab");
        };
    }
}
