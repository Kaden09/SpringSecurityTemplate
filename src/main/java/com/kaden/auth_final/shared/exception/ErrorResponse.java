package com.kaden.auth_final.shared.exception;

import org.springframework.http.HttpStatus;

public record ErrorResponse(
        int status,
        String message
) {
}
