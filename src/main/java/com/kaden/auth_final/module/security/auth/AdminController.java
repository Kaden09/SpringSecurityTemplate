package com.kaden.auth_final.module.security.auth;

import com.kaden.auth_final.module.security.auth.dto.AssignRoleDto;
import com.kaden.auth_final.module.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;

    @PostMapping("/assign-role")
    public ResponseEntity<String> assignRole(@Valid @RequestBody AssignRoleDto dto) {
        return ResponseEntity.ok(userService.assignRole(dto.username(), dto.role()));
    }

    @PostMapping("/revoke-role")
    public ResponseEntity<String> revokeRole(@Valid @RequestBody AssignRoleDto dto) {
        return ResponseEntity.ok(userService.revokeRole(dto.username(), dto.role()));
    }
}