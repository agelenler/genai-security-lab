package com.genai.security.dataaccess;

import com.genai.security.dataaccess.record.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class OrderRepository {

    private final JdbcTemplate jdbc;

    private static final RowMapper<Order> MAPPER = (rs, n) ->
            new Order(rs.getString("reference"), rs.getString("customer"),
                    rs.getInt("age_days"), rs.getBigDecimal("amount"));

    OrderRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Order> vulnerableSearch(String modelValue) {
        // INTENTIONALLY VULNERABLE: even AI-generated text must not become SQL syntax.
        return jdbc.query("SELECT * FROM orders WHERE reference = '" + modelValue + "'", MAPPER);
    }

    public List<Order> protectedSearch(String modelValue, String authenticatedUser) {
        return jdbc.query("SELECT * FROM orders WHERE reference = ? AND customer = ?",
                MAPPER, modelValue, authenticatedUser);
    }

    public Order find(String reference) {
        var result = jdbc.query("SELECT * FROM orders WHERE reference = ?", MAPPER, reference);
        return result.isEmpty() ? null : result.getFirst();
    }
}
