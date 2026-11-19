package com.genai.security.service;

import com.genai.security.dataaccess.OrderRepository;
import com.genai.security.dto.Mode;
import com.genai.security.service.record.Decision;
import com.genai.security.service.record.Proposal;
import org.springframework.stereotype.Service;

@Service
public class RefundPolicyService {

    private final OrderRepository orders;

    public RefundPolicyService(OrderRepository orders) {
        this.orders = orders;
    }

    public Decision evaluate(Proposal proposal, String authenticatedUser, Mode mode) {
        // Both paths are a policy SIMULATION. There is deliberately no payment integration.
        if (mode == Mode.VULNERABLE) {
            return new Decision(
                    "WOULD_EXECUTE",
                    true,
                    "Unsafe backend would refund " + proposal.amount() +
                            " EUR for order " + proposal.orderId() +
                            " without checking ownership, amount or refund policy"
            );
        }


        if (proposal == null || proposal.orderId() == null || proposal.amount() == null) {
            return deny("Missing fields");
        }

        var order = orders.find(proposal.orderId());

        if (order == null || !order.customer().equals(authenticatedUser)) {
            return deny("Order is unavailable to the authenticated user");
        }

        if (proposal.amount().signum() <= 0 || proposal.amount().compareTo(order.amount()) > 0
                || proposal.amount().stripTrailingZeros().scale() > 2) {
            return deny("Amount must be positive, within the order total, and use at most two decimal places");
        }

        if (order.ageDays() > 30) {
            return deny("Order exceeds the 30-day policy");
        }

        return new Decision("REQUIRES_REVIEW", false,
                "Eligible proposal; no execution. " +
                        "A real implementation needs approval bound to this exact action, " +
                        "plus idempotency and remaining-balance checks.");
    }

    private Decision deny(String reason) {
        return new Decision("DENIED", false, reason);
    }
}
