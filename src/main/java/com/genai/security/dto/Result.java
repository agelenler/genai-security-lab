package com.genai.security.dto;

import java.util.List;
import java.util.Map;

public record Result(Scenario scenario, Mode mode, Source source, String model,
                     String user, List<Message> messages, String output, Map<String, Object> evidence,
                     String teachingNote) {
}