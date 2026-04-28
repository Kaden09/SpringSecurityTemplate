package com.kaden.auth_final.module.security.auth.dto;

import java.util.Set;

public record AuthResponseDto(
        Long userId,
        String username,
        String email,
        Set<String> roles
) {}

