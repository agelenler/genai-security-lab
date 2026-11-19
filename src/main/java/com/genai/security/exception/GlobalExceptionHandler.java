package com.genai.security.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    ResponseEntity<Map<String, String>> invalidRequest(Exception ignored) {
        // Do not log rejected prompt contents or echo them in validation errors.
        return ResponseEntity.badRequest().body(Map.of("message",
                "Invalid request. Select a valid scenario, mode and source; input must contain 1–3000 characters."));
    }

    @ExceptionHandler(org.springframework.web.multipart.MaxUploadSizeExceededException.class)
    ResponseEntity<Map<String, String>> oversizedImage(Exception ignored) {
        return ResponseEntity.status(413).body(Map.of("message", "Choose an image up to 5 MB"));
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, String>> upstream(ResponseStatusException error) {
        return ResponseEntity.status(error.getStatusCode()).body(Map.of("message",
                error.getReason() == null ? "Request failed" : error.getReason()));
    }
}
