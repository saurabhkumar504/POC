package com.owasp.lab.controller;

import com.owasp.lab.model.User;
import com.owasp.lab.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Authentication endpoints.
 *
 * REMEDIATION summary:
 *  - VULN-002: loginUnsafe now uses parameterised SQL and a
 *    PasswordEncoder.matches() hash compare.
 *  - VULN-004: passwords are hashed on register before persistence.
 *  - VULN-006: /transfer requires authentication and verifies the
 *    caller's principal matches the source user.
 *  - VULN-009: the /api/login response no longer contains the password.
 *  - VULN-012: /register binds to a server-side DTO and the role is
 *    always forced to "USER".  ADMIN elevation requires a separate,
 *    authenticated flow.
 *  - VULN-015: failed login attempts are logged via SLF4J.
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        User u = userService.loginUnsafe(username, password, passwordEncoder);
        if (u == null) {
            // REMEDIATION (A09:2021): emit a structured warning so
            // brute-force attempts are visible in log aggregation.
            org.slf4j.LoggerFactory.getLogger(AuthController.class)
                    .warn("Failed login attempt for username of length {}",
                            username == null ? 0 : username.length());
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
        // REMEDIATION (A04:2021 / A02:2021): never echo the password
        // (or the password hash) back to the caller.
        return ResponseEntity.ok(Map.of(
                "id", u.getId(),
                "username", u.getUsername(),
                "role", u.getRole()
        ));
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        String email    = body.getOrDefault("email", "");

        // REMEDIATION (A01:2021 / A04:2021): the role is ALWAYS forced
        // to USER server-side.  Even if the caller supplies a role
        // field, it is ignored - ADMIN elevation must go through an
        // authenticated, audited admin-only endpoint.
        User u = new User(username, passwordEncoder.encode(password), email, "USER", 0.0);
        return ResponseEntity.ok(userService.save(u));
    }

    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@RequestBody Map<String, Object> body,
                                       @AuthenticationPrincipal UserDetails caller) {
        Long fromId = ((Number) body.get("fromId")).longValue();
        Long toId   = ((Number) body.get("toId")).longValue();
        Double amount = ((Number) body.get("amount")).doubleValue();

        // REMEDIATION (A01:2021 - IDOR): the caller must own the
        // source account unless they are an ADMIN.
        if (caller == null) {
            throw new AccessDeniedException("Authentication required");
        }
        User from = userService.findByIdUnsafe(fromId);
        if (from == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
        }
        boolean isAdmin = caller.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        if (!isAdmin && !caller.getUsername().equals(from.getUsername())) {
            throw new AccessDeniedException("Cannot transfer from another user's account");
        }

        User to = userService.findByIdUnsafe(toId);
        if (to == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Recipient not found"));
        }
        if (amount == null || amount <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "Amount must be positive"));
        }
        if (from.getBalance() < amount) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient funds"));
        }
        from.setBalance(from.getBalance() - amount);
        to.setBalance(to.getBalance() + amount);
        userService.save(from);
        userService.save(to);

        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "fromBalance", from.getBalance(),
                "toBalance", to.getBalance()
        ));
    }
}
