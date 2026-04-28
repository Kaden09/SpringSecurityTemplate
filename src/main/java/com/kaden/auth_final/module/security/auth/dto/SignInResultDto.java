package com.kaden.auth_final.module.security.auth.dto;

import org.springframework.http.ResponseCookie;

public record SignInResultDto(ResponseCookie accessCookie, ResponseCookie refreshCookie, AuthResponseDto body) {}
