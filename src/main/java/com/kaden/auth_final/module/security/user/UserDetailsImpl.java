package com.kaden.auth_final.module.security.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.kaden.auth_final.module.user.User;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@RequiredArgsConstructor
public class UserDetailsImpl implements UserDetails {
    private final Long id;
    private final String username;
    private final String email;

    @JsonIgnore
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;

    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleName().name()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

    @Override public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    @Override public @Nullable String getPassword() {
        return password;
    }
    @Override public @NonNull String getUsername() {
        return username;
    }

    @Override public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }
    @Override public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }
    @Override public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }
    @Override public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
