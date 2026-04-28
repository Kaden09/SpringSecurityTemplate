package com.kaden.auth_final.module.security.auth.dto;

import org.springframework.http.ResponseCookie;

public record LogoutResultDto(ResponseCookie accessCookie, ResponseCookie refreshCookie) {}