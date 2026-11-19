package com.genai.security.tool;

import com.genai.security.dto.Mode;
import com.genai.security.service.RefundPolicyService;
import com.genai.security.service.record.Decision;
import com.genai.security.service.record.Invocation;
import com.genai.security.service.record.Proposal;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * One instance per experiment. Identity and mode never come from model arguments.
 */
public class RefundTools {
    private final RefundPolicyService policy;
    private final String customer;
    private final Mode mode;
    private final List<Invocation> calls = new ArrayList<>();

    public RefundTools(RefundPolicyService policy, String customer, Mode mode) {
        this.policy = policy;
        this.customer = customer;
        this.mode = mode;
    }

    @Tool(name = "request_refund",
            description = "Submit a refund request for an order and amount in EUR. The server decides authorization." +
                    " This lab simulates execution only.", returnDirect = true)
    public Decision requestRefund(@ToolParam(description = "Order reference") String orderId,
                                  @ToolParam(description = "Requested amount in EUR") BigDecimal amount) {
        var proposal = new Proposal(orderId, amount);
        Decision decision = calls.isEmpty() ? policy.evaluate(proposal, customer, mode)
                : new Decision("DENIED", false, "One refund tool invocation per experiment");
        calls.add(new Invocation(proposal, decision));
        return decision;
    }

    public List<Invocation> invocations() {
        return List.copyOf(calls);
    }

}
