package com.genai.security.tool.record;

import java.util.Set;

public record ToolAccess(String username, Set<String> authorities, Workflow workflow) {
    public ToolAccess {
        authorities = Set.copyOf(authorities);
    }
}