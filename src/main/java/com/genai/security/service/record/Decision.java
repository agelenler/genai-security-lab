package com.genai.security.service.record;

public record Decision(String status, boolean wouldExecute, String reason) {
}