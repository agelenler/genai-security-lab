package com.genai.security.service.record;

import java.math.BigDecimal;

public record Proposal(String orderId, BigDecimal amount) {
}