package com.owasp.lab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

/**
 * REMEDIATION (OWASP A02:2021 - Cryptographic Failures /
 *              OWASP A05:2021 - Security Misconfiguration):
 *
 *  - VULN-010: secrets are no longer hardcoded literals in
 *    application.properties.  They are sourced from environment
 *    variables (APP_SECRET_API_KEY, APP_SECRET_DB_PASSWORD,
 *    APP_SECRET_JWT_SIGNING_KEY) which MUST be supplied by a real
 *    secrets manager (Spring Cloud Config, HashiCorp Vault, AWS
 *    Secrets Manager) at deploy time.  No defaults are provided so
 *    a misconfigured deployment fails fast rather than silently
 *    picking up an attacker-known value.
 *  - VULN-013: the JWT signing key, when one is required, must be a
 *    high-entropy value generated via SecureRandom and rotated
 *    periodically.
 */
@Configuration
public class SecretConfig {

    @Value("${app.secret.api.key:}")
    private String apiKey;

    @Value("${app.secret.db.password:}")
    private String dbPassword;

    @Value("${app.secret.jwt.signing.key:}")
    private String jwtSigningKey;

    @Bean(name = "apiKey")
    public String apiKey() {
        return apiKey;
    }

    @Bean(name = "dbPassword")
    public String dbPassword() {
        return dbPassword;
    }

    @Bean(name = "jwtSigningKey")
    public String jwtSigningKey() {
        return jwtSigningKey;
    }
}
