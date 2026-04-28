package com.kaden.auth_final.module.security.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record AssignRoleDto(
        @NotBlank(message = "Username is required")
        String username,

        @NotBlank(message = "Role is required")
        String role
) {}

