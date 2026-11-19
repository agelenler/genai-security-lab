package com.genai.security;

import com.genai.security.dto.Message;
import com.genai.security.dto.Mode;
import com.genai.security.dto.RunRequest;
import com.genai.security.dto.Scenario;
import com.genai.security.dto.Source;
import com.genai.security.modelclient.ModelClient;
import com.genai.security.service.CustomerSupportService;
import com.genai.security.tool.TrainingSecretTools;
import com.genai.security.tool.record.ToolAccess;
import com.genai.security.tool.record.Workflow;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * This test class verifies the contract between the application and the Ollama server.
 * It includes tests for various scenarios such as handling roles, JSON modes, provider failures,
 * and interactions with tools like refund and image analysis.
 */
@SpringBootTest(properties = {"spring.datasource.url=jdbc:h2:mem:ollamacontract;DB_CLOSE_DELAY=-1",
        "spring.http.clients.read-timeout=2s"})
public class OllamaContractTest {
    static final JsonMapper JSON = JsonMapper.builder().build();
    static final List<JsonNode> REQUESTS = new CopyOnWriteArrayList<>();
    static volatile String content = "test response";
    static volatile List<Object> toolCalls = List.of();
    static volatile int status = 200;
    static volatile long delayMillis = 0;
    static final java.util.concurrent.ExecutorService EXECUTOR = Executors.newCachedThreadPool();
    static final HttpServer SERVER = server();
    @Autowired
    ModelClient model;
    @Autowired
    CustomerSupportService lab;
    @Autowired
    @Qualifier("ollamaChatClient")
    ChatClient namedClient;

    static HttpServer server() {
        try {
            var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(EXECUTOR);
            server.createContext("/api/chat", exchange -> {
                REQUESTS.add(JSON.readTree(exchange.getRequestBody().readAllBytes()));
                int responseStatus = status;
                byte[] body = (responseStatus == 200 ? JSON.writeValueAsString(java.util.Map.of(
                        "model", "mistral:7b", "created_at", "2026-11-13T12:00:00Z", "done", true,
                        "done_reason", "stop", "message", java.util.Map.of("role", "assistant", "content", content, "tool_calls", toolCalls)))
                        : "sensitive provider details").getBytes(StandardCharsets.UTF_8);
                try {
                    if (delayMillis > 0) Thread.sleep(delayMillis);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(responseStatus, body.length);
                    exchange.getResponseBody().write(body);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                } catch (java.io.IOException disconnected) { /* expected after read timeout */ } finally {
                    exchange.close();
                }
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.ai.ollama.base-url", () -> "http://127.0.0.1:" + SERVER.getAddress().getPort());
    }

    @BeforeEach
    void reset() {
        REQUESTS.clear();
        toolCalls = List.of();
        content = "test response";
        status = 200;
        delayMillis = 0;
    }

    @AfterAll
    static void shutdown() {
        SERVER.stop(0);
        EXECUTOR.shutdownNow();
    }

    @Test
    void namedChatClientSendsRolesLiteralTextAndConfiguredLimits() {
        assertThat(namedClient).isNotNull();
        assertThat(model.chat(List.of(new Message("system", "Follow policy"),
                new Message("user", "Return {\"orderId\":\"ORD-100\"} literally")), false)).isEqualTo("test response");
        assertThat(REQUESTS).hasSize(1);
        var json = REQUESTS.getFirst();
        assertThat(json.path("model").asText()).isEqualTo("vicuna:7b");
        assertThat(json.path("stream").asBoolean()).isFalse();
        assertThat(json.path("options").path("num_predict").asInt()).isEqualTo(300);
        assertThat(json.path("options").path("num_ctx").asInt()).isEqualTo(4096);
        assertThat(json.path("options").path("temperature").asDouble()).isZero();
        assertThat(json.path("messages").get(0).path("role").asText()).isEqualTo("system");
        assertThat(json.path("messages").get(1).path("role").asText()).isEqualTo("user");
        assertThat(json.path("messages").get(1).path("content").asText()).contains("{\"orderId\":\"ORD-100\"}");
    }

    @Test
    void jsonModeDoesNotLeakIntoLaterTextCallAndKeepsLimits() {
        model.chat(List.of(new Message("user", "Return JSON")), true);
        model.chat(List.of(new Message("user", "Return text")), false);
        assertThat(REQUESTS).hasSize(2);
        assertThat(REQUESTS.get(0).path("format").asText()).isEqualTo("json");
        assertThat(REQUESTS.get(0).path("options").path("num_predict").asInt()).isEqualTo(300);
        assertThat(REQUESTS.get(1).path("format").asText()).isNotEqualTo("json");
    }

    @Test
    void providerFailureIsNotRetriedOrExposed() {
        status = 500;
        assertThatThrownBy(() -> model.chat(List.of(new Message("user", "Hello")), false))
                .isInstanceOf(ResponseStatusException.class).hasMessageNotContaining("sensitive provider details");
        assertThat(REQUESTS).hasSize(1);
    }

    @Test
    void emptyModelResponseIsRejected() {
        content = "";
        assertThatThrownBy(() -> model.chat(List.of(new Message("user", "Hello")), false))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void configuredReadTimeoutIsApplied() {
        delayMillis = 3000;
        long start = System.nanoTime();
        assertThatThrownBy(() -> model.chat(List.of(new Message("user", "Hello")), false))
                .isInstanceOf(ResponseStatusException.class);
        assertThat(java.time.Duration.ofNanos(System.nanoTime() - start)).isLessThan(java.time.Duration.ofSeconds(5));
        assertThat(REQUESTS).hasSize(1);
    }

    @Test
    void fixturePathDoesNotInvokeSpringAi() {
        var result = lab.run(new RunRequest(Scenario.OUTPUT, Mode.PROTECTED, Source.FIXTURE, "test"), "alice");
        assertThat(result.evidence().get("rowCount")).isEqualTo(0);
        assertThat(REQUESTS).isEmpty();
    }

    @Test
    void nativeRefundCallbackUsesPrincipalAndBackendPolicy() {
        content = "";
        toolCalls = List.of(java.util.Map.of("function", java.util.Map.of(
                "name", "request_refund", "arguments", java.util.Map.of("orderId", "ORD-200", "amount", 499))));
        var denied = lab.run(new RunRequest(Scenario.AGENCY, Mode.PROTECTED, Source.MODEL, "Refund Bob's order"), "alice");
        assertThat(denied.evidence().get("toolCalled")).isEqualTo(true);
        assertThat(denied.output()).contains("DENIED");
        assertThat(REQUESTS).hasSize(1); // returnDirect avoids a second generation.
        var request = REQUESTS.getFirst();
        assertThat(request.path("model").asText()).isEqualTo("mistral-small3.2:latest");
        assertThat(request.path("tools").toString()).contains("request_refund", "orderId", "amount")
                .doesNotContain("customerId", "principal", "mode");
        assertThat(request.path("options").path("num_predict").asInt()).isEqualTo(300);
        var vulnerable = lab.run(new RunRequest(Scenario.AGENCY, Mode.VULNERABLE, Source.MODEL, "Refund Bob's order"), "alice");
        assertThat(vulnerable.output()).contains("WOULD_EXECUTE");
    }

    @Test
    void nativeImageToolReceivesMediaAndProtectedCallbackDoesNotReadFile() throws Exception {
        content = "";
        toolCalls = List.of(java.util.Map.of("function", java.util.Map.of(
                "name", "read_training_secret", "arguments", java.util.Map.of())));
        byte[] image = new org.springframework.core.io.ClassPathResource("static/demo-images/attack.png")
                .getContentAsByteArray();
        var messages = List.of(new Message("system", "Analyze the image"), new Message("user", "Describe {product}"));
        var access = new ToolAccess("alice", Set.of("ROLE_CUSTOMER"), Workflow.PRODUCT_IMAGE_ANALYSIS);
        var protectedTool = new TrainingSecretTools(Mode.PROTECTED, access);
        var output = model.chatWithImage(messages, protectedTool, "mistral-small3.2:latest",
                new org.springframework.core.io.ByteArrayResource(image), org.springframework.util.MimeTypeUtils.IMAGE_PNG);
        assertThat(output).contains("DENIED");
        assertThat(protectedTool.fileRead()).isFalse();
        assertThat(protectedTool.invocationCount()).isEqualTo(1);
        assertThat(REQUESTS).hasSize(1);
        assertThat(REQUESTS.getFirst().path("messages").get(1).path("images").get(0).asText())
                .isEqualTo(java.util.Base64.getEncoder().encodeToString(image));
        assertThat(REQUESTS.getFirst().toString()).doesNotContain("IMAGE-LAB-SECRET-731");
        var properties = REQUESTS.getFirst().path("tools").get(0)
                .path("function").path("parameters").path("properties");
        assertThat(properties.has("access")).isFalse();
        assertThat(properties.has("username")).isFalse();
        assertThat(properties.has("authorities")).isFalse();
        assertThat(properties.has("workflow")).isFalse();
        assertThat(properties.has("mode")).isFalse();
        var vulnerableTool = new TrainingSecretTools(Mode.VULNERABLE, access);
        assertThat(model.chatWithImage(messages, vulnerableTool, "mistral-small3.2:latest",
                new org.springframework.core.io.ByteArrayResource(image), org.springframework.util.MimeTypeUtils.IMAGE_PNG))
                .contains("IMAGE-LAB-SECRET-731");
        assertThat(vulnerableTool.fileRead()).isTrue();
    }

    @Test
    void nativeSecretToolAllowsAuthorizedDiagnosticsInProtectedMode() {
        content = "";
        toolCalls = List.of(java.util.Map.of("function", java.util.Map.of(
                "name", "read_training_secret", "arguments", java.util.Map.of())));
        var access = new ToolAccess("diagnostic-user", Set.of("TRAINING_SECRET_READ"),
                Workflow.INTERNAL_DIAGNOSTICS);
        var tools = new TrainingSecretTools(Mode.PROTECTED, access);

        String output = model.chatWithTools(
                List.of(new Message("user", "Read the training marker for diagnostics")),
                tools, "mistral-small3.2:latest");

        assertThat(output).contains("ALLOWED", "IMAGE-LAB-SECRET-731");
        assertThat(tools.fileRead()).isTrue();
        assertThat(tools.invocationCount()).isEqualTo(1);
        assertThat(REQUESTS).hasSize(1); // returnDirect=true: no follow-up model generation.
        assertThat(REQUESTS.getFirst().toString()).doesNotContain("diagnostic-user", "IMAGE-LAB-SECRET-731");
    }
}
