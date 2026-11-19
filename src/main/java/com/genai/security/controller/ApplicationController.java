package com.genai.security.controller;

import com.genai.security.dto.Result;
import com.genai.security.dto.RunRequest;
import com.genai.security.service.CustomerSupportService;
import com.genai.security.tool.record.ToolAccess;
import com.genai.security.tool.record.Workflow;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class ApplicationController {
    private final CustomerSupportService customerSupportService;

    private final com.genai.security.service.ImageInjectionService imageService;

    ApplicationController(CustomerSupportService customerSupportService,
                          com.genai.security.service.ImageInjectionService imageService) {
        this.customerSupportService = customerSupportService;
        this.imageService = imageService;
    }

    //Protect against a different website forging a request through that user’s browser.
    @GetMapping("/csrf")
    Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }

    @GetMapping("/me")
    Map<String, String> me(Principal principal) {
        return Map.of("user", principal.getName());
    }

    @PostMapping(value = "/run-image", consumes = "multipart/form-data")
    Result runImage(@org.springframework.web.bind.annotation.RequestPart("file") org.springframework.web.multipart.MultipartFile file,
                    @org.springframework.web.bind.annotation.RequestParam("input") String input,
                    @org.springframework.web.bind.annotation.RequestParam("mode") com.genai.security.dto.Mode mode,
                    Authentication authentication) {
        var access = new ToolAccess(authentication.getName(), authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet()), Workflow.PRODUCT_IMAGE_ANALYSIS
        );
        return imageService.run(file, input, mode, access);
    }

    @PostMapping("/run")
    Result run(@Valid @RequestBody RunRequest request, Principal principal) {
        // Never accept a customer ID or tenant identity from a prompt or model response.
        return customerSupportService.run(request, principal.getName());
    }
}
