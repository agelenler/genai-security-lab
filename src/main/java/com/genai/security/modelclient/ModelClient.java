package com.genai.security.modelclient;

import com.genai.security.dto.Message;

import java.util.List;

public interface ModelClient {
    String chatWithTools(List<Message> messages, Object tools, String model);
    String chatWithImage(List<Message> messages, Object tools, String model,
                         org.springframework.core.io.Resource image, org.springframework.util.MimeType mimeType);
    String chat(List<Message> messages, boolean json);
}
