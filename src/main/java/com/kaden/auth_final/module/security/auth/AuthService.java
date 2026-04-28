package com.kaden.auth_final.module.security.auth;

import com.kaden.auth_final.module.refreshToken.RefreshToken;
import com.kaden.auth_final.module.refreshToken.RefreshTokenRepository;
import com.kaden.auth_final.module.role.Role;
import com.kaden.auth_final.module.role.RoleRepository;
import com.kaden.auth_final.module.role.Roles;
import com.kaden.auth_final.module.security.auth.dto.*;
import com.kaden.auth_final.module.security.jwt.JwtUtils;
import com.kaden.auth_final.module.security.user.UserDetailsImpl;
import com.kaden.auth_final.module.user.User;
import com.kaden.auth_final.module.user.UserRepository;
import com.kaden.auth_final.shared.exception.RefreshTokenExpiredException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public String signup(SignUpRequestDto dto) {
        if (userRepository.existsByUsername(dto.username())) {
            throw new IllegalArgumentException("Username already exists: " + dto.username());
        }
        if (userRepository.existsByEmail(dto.email())) {
            throw new IllegalArgumentException("Email already exists: " + dto.email());
        }

        Set<Role> roles = Set.of(roleRepository
                .findByRoleName(Roles.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Role ROLE_USER not found")));

        User user = User.builder()
                .username(dto.username())
                .email(dto.email())
                .password(passwordEncoder.encode(dto.password()))
                .roles(roles)
                .build();

        userRepository.save(user);
        return "User successfully registered";
    }

    @Transactional
    public SignInResultDto signin(SignInRequestDto dto) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.username(), dto.password())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Access token cookie
        ResponseCookie accessCookie = jwtUtils.generateAccessCookie(userDetails.getUsername());

        // Create and persist refresh token
        ResponseCookie refreshCookie = createRefreshToken(userDetails.getUsername());

        Set<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        AuthResponseDto body = new AuthResponseDto(
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        );

        return new SignInResultDto(accessCookie, refreshCookie, body);
    }

    @Transactional
    public RefreshResultDto refresh(String rawRefreshToken) {
        RefreshToken stored = refreshTokenRepository.findByToken(rawRefreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found or already used"));

        if(stored.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(stored);
            throw new RefreshTokenExpiredException("Refresh token has expired, please sign in again");
        }

        String username = stored.getUser().getUsername();

        refreshTokenRepository.delete(stored);
        ResponseCookie newRefreshCookie = createRefreshToken(username);
        ResponseCookie newAccessCookie = jwtUtils.generateAccessCookie(username);

        return new RefreshResultDto(newAccessCookie, newRefreshCookie);
    }

    @Transactional
    public LogoutResultDto logout(String rawRefreshToken) {
        if (rawRefreshToken != null && !rawRefreshToken.isBlank()) {
            refreshTokenRepository.findByToken(rawRefreshToken)
                    .ifPresent(refreshTokenRepository::delete);
        }

        return new LogoutResultDto(
                jwtUtils.getCleanAccessCookie(),
                jwtUtils.getCleanRefreshCookie()
        );
    }

    private ResponseCookie createRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // One refresh token per user — replace any existing
        refreshTokenRepository.deleteByUser(user);

        String tokenValue = jwtUtils.generateRefreshTokenString();
        long expirationMs = jwtUtils.getRefreshExpirationMs();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(tokenValue)
                .expiresAt(Instant.now().plusMillis(expirationMs))
                .build();

        refreshTokenRepository.save(refreshToken);

        return jwtUtils.generateRefreshCookie(tokenValue);
    }
}
