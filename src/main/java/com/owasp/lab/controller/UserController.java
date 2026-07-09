package com.owasp.lab.controller;

import com.owasp.lab.model.User;
import com.owasp.lab.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * User-related REST endpoints.
 *
 * REMEDIATION (OWASP A01:2021 - Broken Access Control / IDOR):
 *  - /api/users is restricted to ADMIN role.
 *  - /api/profile/{id} requires the caller to be the resource owner
 *    OR an ADMIN.
 *  - /api/search continues to use parameterised SQL (see UserService)
 *    and is restricted to authenticated users.
 */
@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/users")
    public List<User> listUsers(@AuthenticationPrincipal UserDetails caller) {
        // REMEDIATION (A01:2021): only ADMIN can enumerate every user.
        if (caller == null || caller.getAuthorities().stream()
                .noneMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
            throw new AccessDeniedException("ADMIN role required");
        }
        return userService.findAll();
    }

    @GetMapping("/profile/{id}")
    public ResponseEntity<User> getProfile(@PathVariable Long id,
                                           @AuthenticationPrincipal UserDetails caller) {
        if (caller == null) {
            throw new AccessDeniedException("Authentication required");
        }
        User target = userService.findByIdUnsafe(id);
        if (target == null) {
            return ResponseEntity.notFound().build();
        }
        boolean isAdmin = caller.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        if (!isAdmin && !caller.getUsername().equals(target.getUsername())) {
            throw new AccessDeniedException("Cannot view another user's profile");
        }
        return ResponseEntity.ok(target);
    }

    @GetMapping("/search")
    public List<User> search(@RequestParam("q") String q) {
        return userService.findByUsernameUnsafe(q);
    }
}
