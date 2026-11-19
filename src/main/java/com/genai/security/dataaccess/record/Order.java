package com.genai.security.dataaccess.record;

import java.math.BigDecimal;

public record Order(String reference, String customer, int ageDays, BigDecimal amount) {
}