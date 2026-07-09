package com.owasp.lab.config;

import com.owasp.lab.model.User;
import com.owasp.lab.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * REMEDIATION (OWASP A07:2021 - Identification and Authentication Failures):
 *
 * Loads user credentials from the JPA repository so Spring Security can
 * authenticate via the standard {@code AuthenticationManager} and
 * {@code UsernamePasswordAuthenticationFilter}.
 *
 * The stored password is the BCrypt hash produced by
 * {@link com.owasp.lab.config.DataSeeder} (and /api/register) and is
 * matched via the configured {@code PasswordEncoder}.  The plaintext
 * password never leaves the authentication filter.
 */
@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public JpaUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return new org.springframework.security.core.userdetails.User(
                u.getUsername(),
                u.getPassword(),
                // Roles are stored as "USER"/"ADMIN"; Spring Security expects "ROLE_...".
                List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole()))
        );
    }
}