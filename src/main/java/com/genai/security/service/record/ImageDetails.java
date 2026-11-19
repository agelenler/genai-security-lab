package com.genai.security.service.record;

public record ImageDetails(byte[] bytes, String mime, int width, int height) {
}
