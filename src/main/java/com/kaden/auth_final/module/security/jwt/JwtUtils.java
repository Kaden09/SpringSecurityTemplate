package com.kaden.auth_final.module.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtils {
    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.access-expiration-ms}")
    private Long accessExpirationMs;

    @Value("${app.jwt.refresh-expiration-ms}")
    private Long refreshExpirationMs;

    @Value("${app.jwt.access-cookie-name}")
    private String accessCookieName;

    @Value("${app.jwt.refresh-cookie-name}")
    private String refreshCookieName;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String generateAccessTokenString(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    public ResponseCookie generateAccessCookie(String username) {
        String jwt = generateAccessTokenString(username);
        return ResponseCookie.from(accessCookieName, jwt)
                .httpOnly(true)
                .secure(false)
                .path("/api")
                .maxAge(accessExpirationMs / 1000)
                .sameSite("Strict")
                .build();
    }

    public String generateRefreshTokenString() {
        return UUID.randomUUID().toString();
    }

    public long getRefreshExpirationMs() {
        return refreshExpirationMs;
    }

    public ResponseCookie generateRefreshCookie(String refreshToken) {
        return ResponseCookie.from(refreshCookieName, refreshToken)
                .httpOnly(true)
                .secure(false)
                .path("/api/auth/refresh")
                .maxAge(refreshExpirationMs / 1000)
                .sameSite("Strict")
                .build();
    }

    public ResponseCookie getCleanAccessCookie() {
        return ResponseCookie.from(accessCookieName, "")
                .path("/api")
                .maxAge(0)
                .httpOnly(true)
                .build();
    }

    public ResponseCookie getCleanRefreshCookie() {
        return ResponseCookie.from(refreshCookieName, "")
                .path("/api/auth/refresh")
                .maxAge(0)
                .httpOnly(true)
                .build();
    }

    public String getAccessTokenFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, accessCookieName);
        return cookie != null ? cookie.getValue() : null;
    }

    public String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, refreshCookieName);
        return cookie != null ? cookie.getValue() : null;
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            throw new JwtException("Invalid JWT signature: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            throw new JwtException("JWT token has expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            throw new JwtException("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new JwtException("JWT claims string is empty: " + e.getMessage());
        }
    }
}
