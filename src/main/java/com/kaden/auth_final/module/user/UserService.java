package com.kaden.auth_final.module.user;

import com.kaden.auth_final.module.role.Role;
import com.kaden.auth_final.module.role.RoleRepository;
import com.kaden.auth_final.module.role.Roles;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Transactional
    public String assignRole(String username, String roleName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        Roles roleEnum = switch (roleName.toLowerCase()) {
            case "admin" -> Roles.ROLE_ADMIN;
            case "user"  -> Roles.ROLE_USER;
            default -> throw new IllegalArgumentException("Unknown role: " + roleName);
        };

        Role role = roleRepository.findByRoleName(roleEnum)
                .orElseThrow(() -> new RuntimeException("Role not found in DB: " + roleEnum));

        if (user.getRoles().contains(role)) {
            return "User '%s' already has role %s".formatted(username, roleEnum);
        }

        user.getRoles().add(role);
        userRepository.save(user);

        return "Role %s successfully assigned to user '%s'".formatted(roleEnum, username);
    }

    @Transactional
    public String revokeRole(String username, String roleName) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        Roles roleEnum = switch (roleName.toLowerCase()) {
            case "admin" -> Roles.ROLE_ADMIN;
            case "user"  -> Roles.ROLE_USER;
            default -> throw new IllegalArgumentException("Unknown role: " + roleName);
        };

        Role role = roleRepository.findByRoleName(roleEnum)
                .orElseThrow(() -> new RuntimeException("Role not found in DB: " + roleEnum));

        if (!user.getRoles().contains(role)) {
            return "User '%s' does not have role %s".formatted(username, roleEnum);
        }

        user.getRoles().remove(role);
        userRepository.save(user);

        return "Role %s successfully revoked from user '%s'".formatted(roleEnum, username);
    }
}
