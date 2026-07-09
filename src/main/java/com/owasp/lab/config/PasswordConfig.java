package com.owasp.lab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * REMEDIATION (OWASP A02:2021 / A07:2021):
 * Provides a {@link PasswordEncoder} bean for the application.
 *
 * <p>{@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
 * returns a {@code DelegatingPasswordEncoder} that prefixes hashes with an
 * algorithm identifier (e.g. {@code {bcrypt}$2a$...}) so that future
 * migrations to Argon2 or SCrypt do not invalidate existing credentials.</p>
 */
@Configuration
public class PasswordConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}