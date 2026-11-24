package com.genai.security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RunRequest(@NotNull Scenario scenario,
                         @NotNull Mode mode,
                         @NotNull Source source,
                         @NotBlank @Size(max = 3000) String input) {
}