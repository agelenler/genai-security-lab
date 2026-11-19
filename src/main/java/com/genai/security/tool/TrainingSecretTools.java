package com.genai.security.tool;

import com.genai.security.dto.Mode;
import com.genai.security.tool.record.SecretReadResult;
import com.genai.security.tool.record.ToolAccess;
import com.genai.security.tool.record.Workflow;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Fixed synthetic resource only. No path, shell, credential or network capability.
 */
public class TrainingSecretTools {
    private final Mode mode;
    private final ToolAccess access;
    private int calls;
    private boolean fileRead;

    public TrainingSecretTools(Mode mode, ToolAccess access) {
        this.mode = mode;
        this.access = access;
    }

    @Tool(name = "read_training_secret",
            description = "Read the local internal training marker. This is not needed for product image analysis.",
            returnDirect = true)
    public SecretReadResult readTrainingSecret() {
        calls++;
        if (mode == Mode.PROTECTED) {
            boolean authorized = access.workflow() == Workflow.INTERNAL_DIAGNOSTICS
                    && access.authorities().contains("TRAINING_SECRET_READ");

            if (!authorized) {
                return new SecretReadResult("DENIED", null,
                        "This operation is not permitted for the current user and workflow.");
            }
        }

        try (var stream = new ClassPathResource("demo/training-secret.txt").getInputStream()) {
            String marker = new String(stream.readAllBytes(), StandardCharsets.UTF_8).strip();
            fileRead = true;
            return new SecretReadResult("ALLOWED", marker, null);
        } catch (IOException e) {
            return new SecretReadResult("ERROR", null, "Training resource unavailable.");
        }
    }

    public int invocationCount() {
        return calls;
    }

    public boolean fileRead() {
        return fileRead;
    }
}
