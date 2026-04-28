package com.kaden.auth_final.module.security.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record SignInRequestDto (
        @NotBlank(message = "Username is required")
        String username,

        @NotBlank(message = "Password is required")
        String password
) {}