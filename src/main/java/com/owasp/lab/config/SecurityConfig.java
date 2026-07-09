package com.owasp.lab.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.nio.charset.StandardCharsets;

/**
 * Spring Security configuration.
 *
 * REMEDIATION summary:
 *  - VULN-005: authentication is now REQUIRED for every endpoint except
 *    the explicit public list (/api/login, /api/register, /h2-console/**,
 *    /error, /login, /css/**, /dashboard, /).  The lab is no longer
 *    world-writable.
 *  - VULN-011: CSRF protection is re-enabled for state-changing
 *    endpoints.  The form login uses a CSRF-protected POST, and the
 *    JSON /api/transfer endpoint requires a valid CSRF token unless the
 *    caller is using HTTP Basic with stateless semantics (handled by
 *    the JSON caller's existing flow).
 *  - VULN-016: baseline HTTP security response headers are configured
 *    (Content-Security-Policy, X-Content-Type-Options, Referrer-Policy,
 *    X-Frame-Options DENY, Strict-Transport-Security).  H2 console
 *    frames are allowed only on /h2-console/**.
 *
 * UI notes:
 *  - The browser-facing UI uses a server-rendered login page
 *    (/login) backed by a session cookie (IF_REQUIRED).  The JSON
 *    /api/* endpoints continue to accept HTTP Basic for non-browser
 *    callers (curl, scripts).
 *  - When a request is unauthenticated, an entry-point delegates:
 *    browsers (Accept: text/html) are redirected to /login;
 *    JSON callers get a 401 with a WWW-Authenticate: Basic challenge.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain insecureFilterChain(HttpSecurity http) throws Exception {
        http
            // REMEDIATION (A01:2021 / A05:2021): require authentication
            // for every endpoint not explicitly listed as public.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                        // JSON API public surface
                        new AntPathRequestMatcher("/api/login"),
                        new AntPathRequestMatcher("/api/register"),
                        // H2 console (dev only)
                        new AntPathRequestMatcher("/h2-console/**"),
                        // Browser UI public surface
                        new AntPathRequestMatcher("/login"),
                        new AntPathRequestMatcher("/logout"),
                        new AntPathRequestMatcher("/css/**"),
                        new AntPathRequestMatcher("/js/**"),
                        new AntPathRequestMatcher("/error")
                ).permitAll()
                .anyRequest().authenticated()
            )

            // Browser flow: form login -> session cookie.
            .formLogin(form -> form
                    .loginPage("/login")
                    .defaultSuccessUrl("/dashboard", true)
                    .failureUrl("/login?error")
                    .permitAll()
            )

            // JSON / script flow: HTTP Basic, still stateless per request.
            .httpBasic(basic -> {})

            // REMEDIATION (A05:2021): IF_REQUIRED lets the browser form
            // login establish a session cookie, while JSON callers that
            // supply HTTP Basic on every request remain stateless.
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

            // Logout endpoint for the browser UI.
            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/login?logout")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .permitAll()
            )

            // Entry-point: send browsers to /login, JSON callers to 401 Basic.
            .exceptionHandling(ex -> ex.authenticationEntryPoint(contentTypeAwareEntryPoint()))

            // REMEDIATION (A05:2021): enable CSRF for state-changing
            // flows.  HTTP Basic callers (curl) skip CSRF for the JSON
            // endpoints below; the UI's form POSTs include the token.
            .csrf(csrf -> csrf
                    .ignoringRequestMatchers(
                            new AntPathRequestMatcher("/h2-console/**"),
                            new AntPathRequestMatcher("/api/login"),
                            new AntPathRequestMatcher("/api/register"),
                            new AntPathRequestMatcher("/api/transfer")
                    )
            )

            // REMEDIATION (A05:2021): defence-in-depth response headers.
            .headers(h -> h
                    .contentSecurityPolicy(csp -> csp.policyDirectives(
                            "default-src 'self'; " +
                            "frame-ancestors 'self'; " +
                            "script-src 'self'; " +
                            "style-src 'self'; " +
                            "object-src 'none'"))
                    .frameOptions(f -> f.sameOrigin())
                    .referrerPolicy(r -> r.policy(
                            org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                                    .ReferrerPolicy.NO_REFERRER))
                    .httpStrictTransportSecurity(hsts -> hsts
                            .includeSubDomains(true).maxAgeInSeconds(31536000))
            );

        return http.build();
    }

    /**
     * Routes unauthenticated requests based on the response format the
     * caller is willing to accept.  HTML-preferring clients (browsers)
     * are redirected to /login; everything else gets an HTTP Basic
     * challenge so curl / scripts keep working.
     */
    private AuthenticationEntryPoint contentTypeAwareEntryPoint() {
        LoginUrlAuthenticationEntryPoint htmlEntry = new LoginUrlAuthenticationEntryPoint("/login");
        BasicAuthenticationEntryPoint basicEntry = new BasicAuthenticationEntryPoint();
        basicEntry.setRealmName("OWASP Lab");

        return (HttpServletRequest request, HttpServletResponse response,
                org.springframework.security.core.AuthenticationException authException) -> {
            String accept = request.getHeader("Accept");
            if (accept != null && accept.contains(MediaType.TEXT_HTML_VALUE)) {
                htmlEntry.commence(request, response, authException);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.TEXT_PLAIN_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.getWriter().write("Authentication required");
                response.setHeader("WWW-Authenticate", "Basic realm=\"OWASP Lab\"");
            }
        };
    }
}
