package com.kaden.auth_final.shared.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ErrorHandler {
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<@NonNull ErrorResponse> handleBadCredentials(
            final BadCredentialsException ex) {
        return error(HttpStatus.UNAUTHORIZED, "Неверный логин или пароль");
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<@NonNull ErrorResponse> handleUserNotFound(
            final UsernameNotFoundException ex) {
        return error(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<@NonNull ErrorResponse> handleDisabled(final DisabledException ex) {
        return error(HttpStatus.FORBIDDEN, "Account disabled " + ex.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<@NonNull ErrorResponse> handleAccessDenied(final AccessDeniedException ex) {
        return error(HttpStatus.FORBIDDEN, "No access rights to the resource " + ex.getMessage());
    }

    @ExceptionHandler({JwtException.class, ExpiredJwtException.class})
    public ResponseEntity<@NonNull ErrorResponse> handleJwt(final Exception ex) {
        return error(HttpStatus.UNAUTHORIZED, "Invalid or expired JWT token " + ex.getMessage());
    }

    @ExceptionHandler(RefreshTokenExpiredException.class)
    public ResponseEntity<@NonNull ErrorResponse> handleRefreshTokenExpired(final RefreshTokenExpiredException ex) {
        return error(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<@NonNull ErrorResponse> handleIllegalArgument(final IllegalArgumentException ex) {
        return error(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<@NonNull ErrorResponse> handleValidation(final MethodArgumentNotValidException ex) {
        return error(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<@NonNull ErrorResponse> handleGeneral(final Exception e) {
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "Server error: " + e.getMessage());
    }

    private ResponseEntity<@NonNull ErrorResponse> error(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(
                new ErrorResponse(status.value(), message)
        );
    }
}
