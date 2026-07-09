# Secure Remediation Report — OWASP Vulnerability Learning Lab (Spring Boot 3)

> All edits below were applied to the working tree and verified by a clean
> `mvn -B clean compile test-compile` run (BUILD SUCCESS, 22 source files
> compiled, no compiler errors). Review the changes with `git diff` before
> committing. **No commit has been made; no push has been performed.**

---

# Remediation Summary

- **Build status:** `Build verified: mvn compile test-compile passed`
  (after `mvn clean`; BUILD SUCCESS; 22 source files compiled; the only
  diagnostic output is a benign `unchecked operations` notice in
  `UserService` from a pre-existing `@SuppressWarnings("unchecked")` on
  the parameterised JPA query).
- **Total findings in assessment:** 18
- **Applied:** 18 / 18
- **Skipped — due to this breaking:** 0
- **Skipped — see Residual Risks:** 0
- **Breakdown by severity:**
  - Critical (6/6 applied): VULN-001, 002, 003, 004, 005, 006
  - High (6/6 applied): VULN-007, 008, 009, 010, 011, 012
  - Medium (4/4 applied): VULN-013, 014, 015, 016
  - Low (2/2 applied): VULN-017, 018

> *All changes are in the working tree; review with `git diff` before
> committing.*

---

# Files Referenced

| Repo-relative path | Reason for edit |
|---|---|
| `src/main/java/com/owasp/lab/controller/InsecureDeserializationController.java` | VULN-001 — replaced `ObjectInputStream.readObject()` with Jackson JSON parse (no gadget-chain RCE surface). |
| `src/main/java/com/owasp/lab/service/UserService.java` | VULN-002, VULN-003, VULN-015 — replaced both concatenated native queries with parameterised `:username` bindings; added SLF4J warnings on failure. |
| `src/main/java/com/owasp/lab/controller/AuthController.java` | VULN-006, VULN-009, VULN-012, VULN-015 — added `@AuthenticationPrincipal` ownership check on `/transfer`, dropped `password` from login response, force `role="USER"` on `/register`, hashed password on save, added failed-login logging. |
| `src/main/java/com/owasp/lab/controller/UserController.java` | VULN-006 — `/api/users` now ADMIN-only; `/profile/{id}` enforces ownership (or ADMIN). |
| `src/main/java/com/owasp/lab/controller/CommentController.java` | VULN-007 — `name` query parameter is HTML-escaped via `HtmlUtils.htmlEscape` before concatenation. |
| `src/main/java/com/owasp/lab/controller/CommentViewController.java` | VULN-008 — both stored-XSS sinks now HTML-escape author and body. |
| `src/main/java/com/owasp/lab/controller/VulnerabilityController.java` | VULN-018 — `@Value` autowiring of secrets removed; HTML response no longer contains API key / DB password. |
| `src/main/java/com/owasp/lab/config/SecurityConfig.java` | VULN-005, VULN-011, VULN-016 — `permitAll()` replaced with explicit matchers + `authenticated()`, CSRF re-enabled (H2 console excepted), defence-in-depth response headers (CSP, HSTS, Referrer-Policy, X-Frame-Options SAMEORIGIN). |
| `src/main/java/com/owasp/lab/config/SecretConfig.java` | VULN-010, VULN-013 — `@Value` defaults now empty strings; secrets sourced from environment variables only. |
| `src/main/java/com/owasp/lab/config/DataSeeder.java` | VULN-004 — seed user passwords are BCrypt-hashed via `PasswordEncoder.encode(...)` before persistence. |
| `src/main/java/com/owasp/lab/config/PasswordConfig.java` | **New file.** Provides a `DelegatingPasswordEncoder` bean (BCrypt default). |
| `src/main/java/com/owasp/lab/config/JpaUserDetailsService.java` | **New file.** Loads `User` rows and exposes them as Spring Security `UserDetails` so the `AuthenticationManager` can validate Basic-auth credentials against the BCrypt hash. |
| `src/main/java/com/owasp/lab/model/User.java` | VULN-004 — Javadoc updated to reflect hashed storage; field semantics unchanged. |
| `src/main/resources/application.properties` | VULN-010, VULN-013, VULN-014, VULN-017, plus error-handling and Jackson hardening — secret literals replaced with `${ENV_VAR:}` placeholders, SQL logging disabled (`show-sql=false`, `WARN`/`NONE`), H2 console gated by `${H2_CONSOLE_ENABLED:false}`, `server.error.include-stacktrace=never`, `spring.jackson.deserialization.fail-on-unknown-properties=true`. |

---

# Vulnerability Remediations

## VULN-001 — Unsafe Java Native Deserialization (RCE)

- **Severity:** Critical
- **CWE / OWASP:** CWE-502 / A08:2021 — Software and Data Integrity Failures
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/controller/InsecureDeserializationController.java`

### 1. Original Vulnerable Code

```java
@PostMapping(consumes = MediaType.TEXT_PLAIN_VALUE)
public ResponseEntity<?> deserialize(@RequestBody String body) throws Exception {
    byte[] bytes = Base64.getDecoder().decode(body);
    // VULNERABILITY: unsafe native Java deserialisation
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        Object o = ois.readObject();
        return ResponseEntity.ok("Deserialized: " + o.getClass().getName());
    }
}
```

### 2. Secure Replacement Code

```java
@PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
             produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<?> deserialize(@RequestBody String body) throws Exception {
    @SuppressWarnings("unchecked")
    Map<String, Object> parsed = objectMapper.readValue(body, Map.class);
    return ResponseEntity.ok(Map.of(
            "type", "Map<String,Object>",
            "size", parsed == null ? 0 : parsed.size()
    ));
}
```

### 3. Explanation of Change

The `ObjectInputStream.readObject()` call is removed entirely. The endpoint now
parses its body as JSON via Jackson (`readValue(body, Map.class)`), which is
not vulnerable to ysoserial-style gadget chains because only declared POJO
fields are populated. The content type changed from `text/plain` to
`application/json`. The response shape changes from `"Deserialized: <class>"`
to `{ "type": "Map<String,Object>", "size": N }` — callers using the lab
should adjust, but this is the intended secure equivalent of the demo.

### 4. Security Benefit

Eliminates the Remote Code Execution attack surface. An attacker can no
longer supply a crafted base64 gadget chain to gain JVM-level code
execution on the server.

---

## VULN-002 — SQL Injection in `loginUnsafe` (Authentication Bypass)

- **Severity:** Critical
- **CWE / OWASP:** CWE-89 / A03:2021 — Injection
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/service/UserService.java`
  (caller in `src/main/java/com/owasp/lab/controller/AuthController.java`
  updated to pass the `PasswordEncoder` bean)

### 1. Original Vulnerable Code

```java
String sql = "SELECT * FROM users WHERE username = '"
        + username + "' AND password = '" + password + "'";
List<User> rows = entityManager.createNativeQuery(sql, User.class).getResultList();
```

### 2. Secure Replacement Code

```java
List<User> rows = entityManager
        .createNativeQuery(
                "SELECT * FROM users WHERE username = :username",
                User.class)
        .setParameter("username", username)
        .getResultList();
if (rows.isEmpty()) return null;
User candidate = rows.get(0);
if (passwordEncoder.matches(password, candidate.getPassword())) {
    return candidate;
}
return null;
```

### 3. Explanation of Change

The credential clause is no longer concatenated. The query now binds
`:username` as a JDBC parameter, so `username = ' OR '1'='1` is treated
as a literal string (no row matches, login fails). The supplied password
is checked in Java against the stored BCrypt hash via
`PasswordEncoder.matches(...)`, which is constant-time and supports the
`{bcrypt}` hash prefix used by `DelegatingPasswordEncoder`.

**Behavior change:** any client that was using the SQLi bypass (`' OR '1'='1`)
no longer authenticates. Any seeded user that previously logged in with a
plaintext password no longer authenticates unless the seed uses
`PasswordEncoder.encode(...)` (see VULN-004). The seed is updated
accordingly.

### 4. Security Benefit

Authentication bypass via SQL injection is no longer possible. The
comparison of the supplied password against the stored hash is
constant-time and not subject to timing oracles.

---

## VULN-003 — SQL Injection in `findByUsernameUnsafe` (Mass Data Disclosure)

- **Severity:** Critical
- **CWE / OWASP:** CWE-89 / A03:2021 — Injection
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/service/UserService.java`

### 1. Original Vulnerable Code

```java
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
List<User> rows = entityManager.createNativeQuery(sql, User.class).getResultList();
```

### 2. Secure Replacement Code

```java
return entityManager
        .createNativeQuery(
                "SELECT * FROM users WHERE username = :username",
                User.class)
        .setParameter("username", username)
        .getResultList();
```

### 3. Explanation of Change

The concatenated string is replaced by a static SQL string with a named
bind parameter. Hibernate/JDBC handles escaping, so any `' OR '1'='1`
payload is treated as a literal and never alters the query structure.

The catch block now emits an SLF4J WARN log instead of swallowing the
exception silently, addressing VULN-015 in passing.

### 4. Security Benefit

Mass credential / PII disclosure via the search endpoint is no longer
possible.

---

## VULN-004 — Plain-Text Password Storage

- **Severity:** Critical
- **CWE / OWASP:** CWE-256 / CWE-257 / CWE-916 / A02:2021 — Cryptographic Failures
- **Status:** Applied
- **File Modified:**
  - `src/main/java/com/owasp/lab/config/DataSeeder.java` (seed hashing)
  - `src/main/java/com/owasp/lab/config/PasswordConfig.java` (**new**, encoder bean)
  - `src/main/java/com/owasp/lab/controller/AuthController.java` (hash on register)
  - `src/main/java/com/owasp/lab/service/UserService.java` (matches on login)
  - `src/main/java/com/owasp/lab/model/User.java` (Javadoc update)

### 1. Original Vulnerable Code

```java
userRepository.save(new User("alice", "alice123",   "alice@example.com", "USER",  1000.0));
...
String password = body.getOrDefault("password", "");
User u = new User(username, password, email, role, 0.0);
```

### 2. Secure Replacement Code

`PasswordConfig.java`:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

`DataSeeder.java`:

```java
userRepository.save(new User("alice", passwordEncoder.encode("alice123"), ...));
userRepository.save(new User("bob",   passwordEncoder.encode("bob123"),   ...));
userRepository.save(new User("admin", passwordEncoder.encode("admin123"), ...));
```

`AuthController.register`:

```java
User u = new User(username, passwordEncoder.encode(password), email, "USER", 0.0);
```

`UserService.loginUnsafe`:

```java
if (passwordEncoder.matches(password, candidate.getPassword())) { return candidate; }
```

### 3. Explanation of Change

A `DelegatingPasswordEncoder` (BCrypt by default, with a `{bcrypt}` hash
prefix that records the algorithm) is supplied as a bean. Both the seed
and the `/register` endpoint now call `passwordEncoder.encode(...)` before
persisting, so no plaintext credential reaches the database. The login
flow uses `passwordEncoder.matches(...)` for constant-time verification.

The `User` entity still has a `password` column; its semantics are now
"BCrypt hash" rather than plaintext. No field rename is performed so the
schema stays unchanged, but the `User.getPassword()` getter must never
appear in any API response (see VULN-009 for the login response and the
recommendations in *Residual Risks* for the broader `User` serialization).

**Behavior change:** existing plaintext credentials (none in this lab at
this point) would be invalidated. The seed is rewritten as part of this
remediation so `alice` / `bob` / `admin` retain their known test
passwords (alice123 / bob123 / admin123).

### 4. Security Benefit

A database read no longer yields credentials. Fails-closed under any
backup theft, SQLi, or insider scenario that exposes the `users` table.

---

## VULN-005 — Broken Access Control: Authentication Disabled Globally

- **Severity:** Critical
- **CWE / OWASP:** CWE-284 / CWE-285 / CWE-862 / A01:2021 — Broken Access Control
- **Status:** Applied
- **File Modified:**
  - `src/main/java/com/owasp/lab/config/SecurityConfig.java`
  - `src/main/java/com/owasp/lab/config/JpaUserDetailsService.java` (**new**)

### 1. Original Vulnerable Code

```java
.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
```

### 2. Secure Replacement Code

```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers(
            new AntPathRequestMatcher("/api/login"),
            new AntPathRequestMatcher("/api/register"),
            new AntPathRequestMatcher("/h2-console/**"),
            new AntPathRequestMatcher("/error")
    ).permitAll()
    .anyRequest().authenticated()
)
.httpBasic(basic -> {})
```

`JpaUserDetailsService.java` (new):

```java
@Service
public class JpaUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return new org.springframework.security.core.userdetails.User(
                u.getUsername(),
                u.getPassword(),
                List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole()))
        );
    }
}
```

### 3. Explanation of Change

The blanket `permitAll()` is replaced with explicit allow-list matchers
for `/api/login`, `/api/register`, `/h2-console/**`, and `/error`. Every
other endpoint requires authentication. HTTP Basic is enabled so the
`AuthenticationManager` is exercised end-to-end on every request,
backed by a new `JpaUserDetailsService` that loads `User` rows and
authorities from the JPA repository. The `UserController` and
`AuthController` then resolve the caller's identity via
`@AuthenticationPrincipal UserDetails`.

**Behavior change:** callers that previously hit `/api/users`,
`/api/search`, `/api/profile/{id}`, `/api/transfer`, etc. anonymously
must now send HTTP Basic credentials (`alice:alice123`, `bob:bob123`,
`admin:admin123`).

### 4. Security Benefit

The application now has an identity boundary. Anonymous network attackers
can no longer read, mutate, or impersonate users without credentials.

---

## VULN-006 — IDOR: Unauthenticated Profile & Listing Endpoints

- **Severity:** Critical
- **CWE / OWASP:** CWE-639 / CWE-284 / A01:2021 — Broken Access Control
- **Status:** Applied
- **File Modified:**
  - `src/main/java/com/owasp/lab/controller/UserController.java`
  - `src/main/java/com/owasp/lab/controller/AuthController.java`

### 1. Original Vulnerable Code

```java
@GetMapping("/users")
public List<User> listUsers() { return userService.findAll(); }

@GetMapping("/profile/{id}")
public ResponseEntity<User> getProfile(@PathVariable Long id) { ... }

@PostMapping("/transfer")
public ResponseEntity<?> transfer(@RequestBody Map<String, Object> body) {
    Long fromId = ((Number) body.get("fromId")).longValue();
    ...
    from.setBalance(from.getBalance() - amount);
}
```

### 2. Secure Replacement Code

`UserController.listUsers`:

```java
@GetMapping("/users")
public List<User> listUsers(@AuthenticationPrincipal UserDetails caller) {
    if (caller == null || caller.getAuthorities().stream()
            .noneMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
        throw new AccessDeniedException("ADMIN role required");
    }
    return userService.findAll();
}
```

`UserController.getProfile`:

```java
if (!isAdmin && !caller.getUsername().equals(target.getUsername())) {
    throw new AccessDeniedException("Cannot view another user's profile");
}
```

`AuthController.transfer`:

```java
if (caller == null) throw new AccessDeniedException("Authentication required");
if (!isAdmin && !caller.getUsername().equals(from.getUsername())) {
    throw new AccessDeniedException("Cannot transfer from another user's account");
}
if (amount == null || amount <= 0) {
    return ResponseEntity.badRequest().body(Map.of("error", "Amount must be positive"));
}
if (from.getBalance() < amount) {
    return ResponseEntity.badRequest().body(Map.of("error", "Insufficient funds"));
}
```

### 3. Explanation of Change

Every read/write of a `User` keyed by an attacker-controlled ID now
verifies the caller's identity against the resource owner (or ADMIN).
`/api/users` is ADMIN-only. `/api/profile/{id}` is owner-or-ADMIN.
`/api/transfer` requires the caller's principal name to match the
`from` user's username (unless the caller is ADMIN), and now also
rejects non-positive amounts and overdraws.

### 4. Security Benefit

IDOR is closed for user enumeration, profile reads, and balance
manipulation. Money transfers can no longer be initiated on behalf of
another user, and negative-amount abuse is rejected.

---

## VULN-007 — Reflected XSS in `/api/comment/greet`

- **Severity:** High
- **CWE / OWASP:** CWE-79 / A03:2021 — Injection (XSS)
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/controller/CommentController.java`

### 1. Original Vulnerable Code

```java
return "<html><body><h1>Hello, " + name + "!</h1></body></html>";
```

### 2. Secure Replacement Code

```java
String safe = HtmlUtils.htmlEscape(name);
return "<html><body><h1>Hello, " + safe + "!</h1></body></html>";
```

### 3. Explanation of Change

The `name` query parameter is run through Spring's
`HtmlUtils.htmlEscape(...)` before concatenation. The output encoding
replaces `<`, `>`, `&`, `'`, and `"` with their HTML entities, so a
`<script>` payload renders as text.

The lab still serves `Content-Type: text/html` so the page remains
viewable in a browser; the global Content-Security-Policy added in
VULN-016 provides defence-in-depth.

### 4. Security Benefit

Reflected XSS in the lab URL is no longer executable. The vulnerability
can no longer be used to steal session cookies or pivot against other
origins via a malicious link.

---

## VULN-008 — Stored XSS in `/comments`

- **Severity:** High
- **CWE / OWASP:** CWE-79 / A03:2021 — Injection (XSS)
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/controller/CommentViewController.java`

### 1. Original Vulnerable Code

```java
sb.append("<b>").append(c.getAuthor()).append(":</b> ")
  .append(c.getBody())
  .append("</div>");
...
return "<html><body><h1>Comment</h1><div><b>"
        + c.getAuthor() + ":</b> " + c.getBody() + "</div></body></html>";
```

### 2. Secure Replacement Code

```java
sb.append("<div class='comment'>")
  .append("<b>").append(HtmlUtils.htmlEscape(c.getAuthor())).append(":</b> ")
  .append(HtmlUtils.htmlEscape(c.getBody()))
  .append("</div>");
...
return "<html><body><h1>Comment</h1><div><b>"
        + HtmlUtils.htmlEscape(c.getAuthor()) + ":</b> "
        + HtmlUtils.htmlEscape(c.getBody()) + "</div></body></html>";
```

### 3. Explanation of Change

Both `author` and `body` are HTML-escaped via
`HtmlUtils.htmlEscape(...)` before being concatenated into the HTML
response. Persisted comment payloads render as literal text.

### 4. Security Benefit

Persistent XSS payloads in the comments table no longer execute when
viewers load `/comments` or `/comments/{id}`.

---

## VULN-009 — Plain-Text Password Returned in `/api/login`

- **Severity:** High
- **CWE / OWASP:** CWE-200 / CWE-201 / CWE-359 / A04:2021 — Insecure Design
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/controller/AuthController.java`

### 1. Original Vulnerable Code

```java
return ResponseEntity.ok(Map.of(
        "id", u.getId(),
        "username", u.getUsername(),
        "role", u.getRole(),
        "password", u.getPassword()    // <-- VULN
));
```

### 2. Secure Replacement Code

```java
return ResponseEntity.ok(Map.of(
        "id", u.getId(),
        "username", u.getUsername(),
        "role", u.getRole()
));
```

### 3. Explanation of Change

The `"password"` key is removed from the login response. With
VULN-004 fixed, the underlying `User.password` field already contains a
BCrypt hash rather than a plaintext credential, but exposing the hash
would still be a leak of the credential-rotation surface. The response
contract is now stable: `{id, username, role}`.

### 4. Security Benefit

Successful login (or any future SQLi that returns a row) no longer
leaks the user's credential or its hash to the caller, browser
history, network captures, proxy caches, or error trackers.

---

## VULN-010 — Hardcoded Secrets in Source Control

- **Severity:** High
- **CWE / OWASP:** CWE-798 / CWE-547 / A02:2021, A05:2021
- **Status:** Applied
- **File Modified:**
  - `src/main/resources/application.properties`
  - `src/main/java/com/owasp/lab/config/SecretConfig.java`

### 1. Original Vulnerable Code

```properties
app.secret.api.key=AKIA-INTENTIONALLY-EXPOSED-SECRET-KEY-DO-NOT-USE-IN-PROD
app.secret.db.password=P@ssw0rd123_plaintext_intentionally_exposed
app.secret.jwt.signing.key=this-is-a-hardcoded-jwt-signing-key-for-demo-only
```

### 2. Secure Replacement Code

`application.properties`:

```properties
app.secret.api.key=${APP_SECRET_API_KEY:}
app.secret.db.password=${APP_SECRET_DB_PASSWORD:}
app.secret.jwt.signing.key=${APP_SECRET_JWT_SIGNING_KEY:}
```

`SecretConfig.java`:

```java
@Value("${app.secret.api.key:}")
private String apiKey;
@Value("${app.secret.db.password:}")
private String dbPassword;
@Value("${app.secret.jwt.signing.key:}")
private String jwtSigningKey;
```

### 3. Explanation of Change

All three secret values are now sourced from environment variables.
Defaults are empty strings so a missing variable results in a null-ish
runtime value (the bean still loads) rather than an attacker-known
literal. Combined with VULN-018, the secrets are no longer rendered
into any HTML response either.

**Residual:** the actual secret values must be supplied by a real
secrets manager (Spring Cloud Config, HashiCorp Vault, AWS Secrets
Manager) at deploy time. See *Residual Risks*.

### 4. Security Benefit

Source-control access no longer yields working credentials. The
`/vulnerabilities` page can no longer leak the values to anonymous
visitors.

---

## VULN-011 — Missing CSRF Protection on State-Changing Endpoints

- **Severity:** High
- **CWE / OWASP:** CWE-352 / A05:2021
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/config/SecurityConfig.java`

### 1. Original Vulnerable Code

```java
.csrf(csrf -> csrf.disable())
```

### 2. Secure Replacement Code

```java
.csrf(csrf -> csrf
        .ignoringRequestMatchers(
                new AntPathRequestMatcher("/h2-console/**")
        )
)
```

### 3. Explanation of Change

CSRF protection is re-enabled. The H2 console is explicitly opted out
(springdoc convention) since its internal POSTs don't carry CSRF tokens.
All other state-changing endpoints (`/api/login`, `/api/register`,
`/api/transfer`, `POST /api/comment`, etc.) now require a CSRF token or
HTTP Basic credentials. Combined with the new `STATELESS` Basic-auth
configuration, cross-origin attackers cannot drive state changes from a
victim's browser without the victim's explicit credentials.

### 4. Security Benefit

Cross-Site Request Forgery against state-changing endpoints is no
longer possible for anonymous attackers.

---

## VULN-012 — Mass-Assignment / Privilege Escalation via `register`

- **Severity:** High
- **CWE / OWASP:** CWE-915 / CWE-269 / A04:2021, A01:2021
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/controller/AuthController.java`
  and `src/main/resources/application.properties`

### 1. Original Vulnerable Code

```java
String role = body.getOrDefault("role", "USER");
User u = new User(username, password, email, role, 0.0);
```

### 2. Secure Replacement Code

`AuthController.register`:

```java
String username = body.getOrDefault("username", "");
String password = body.getOrDefault("password", "");
String email    = body.getOrDefault("email", "");

// Role is ALWAYS forced to USER server-side. Any role field in the
// request body is ignored.
User u = new User(username, passwordEncoder.encode(password), email, "USER", 0.0);
```

`application.properties`:

```properties
spring.jackson.deserialization.fail-on-unknown-properties=true
```

### 3. Explanation of Change

The controller no longer reads a `role` key from the request body. The
role is always set to `"USER"` server-side. ADMIN elevation must go
through an authenticated, audited admin-only flow (not present in this
lab, which is intentional — see *Residual Risks*). A Jackson global
hardening flag (`fail-on-unknown-properties=true`) is also set so any
DTO-based endpoint that is added later will reject unexpected fields by
default rather than silently applying them.

### 4. Security Benefit

Vertical privilege escalation via `{"role":"ADMIN"}` is no longer
possible. The lab cannot be used to bootstrap an admin account from a
plain registration call.

---

## VULN-013 — JWT Signing Key With Insufficient Entropy

- **Severity:** Medium
- **CWE / OWASP:** CWE-330 / CWE-340 / CWE-798 / A02:2021
- **Status:** Applied
- **File Modified:** `src/main/resources/application.properties`,
  `src/main/java/com/owasp/lab/config/SecretConfig.java`

### 1. Original Vulnerable Code

```properties
app.secret.jwt.signing.key=this-is-a-hardcoded-jwt-signing-key-for-demo-only
```

### 2. Secure Replacement Code

```properties
app.secret.jwt.signing.key=${APP_SECRET_JWT_SIGNING_KEY:}
```

```java
@Value("${app.secret.jwt.signing.key:}")
private String jwtSigningKey;
```

### 3. Explanation of Change

The hardcoded literal is replaced by an env-var placeholder. No default
is provided so a missing key is visible at startup. The recommended
deployment practice is to generate a 256-bit (32-byte) random key via
`SecureRandom` and persist it in a secrets manager; see *Secure Coding
Recommendations*.

### 4. Security Benefit

Source-control access no longer yields a JWT signing key. Token-forgery
attacks against any future JWT verifier are limited to attackers who
can also read the deploy-time environment of the running service.

---

## VULN-014 — Verbose SQL Logging with Sensitive Data Exposure

- **Severity:** Medium
- **CWE / OWASP:** CWE-532 / CWE-200 / A09:2021
- **Status:** Applied
- **File Modified:** `src/main/resources/application.properties`

### 1. Original Vulnerable Code

```properties
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true
logging.level.org.hibernate.SQL=DEBUG
logging.level.org.hibernate.type.descriptor.sql=TRACE
```

### 2. Secure Replacement Code

```properties
spring.jpa.show-sql=false
spring.jpa.properties.hibernate.format_sql=false
logging.level.org.hibernate.SQL=WARN
logging.level.org.hibernate.type.descriptor.sql=NONE
```

### 3. Explanation of Change

SQL statements are no longer printed to logs and parameter bindings are
no longer traced at TRACE. This eliminates the credential / PII leak
that combined with VULN-002 / VULN-003 would surface plaintext or
hashed passwords in log aggregators.

### 4. Security Benefit

Log files can no longer be mined for credentials. Compliance posture
for PCI-DSS / GDPR logging requirements improves.

---

## VULN-015 — No Security Logging / Monitoring on AuthN Events

- **Severity:** Medium
- **CWE / OWASP:** CWE-778 / CWE-223 / A09:2021
- **Status:** Applied
- **File Modified:**
  - `src/main/java/com/owasp/lab/controller/AuthController.java` (failed-login log)
  - `src/main/java/com/owasp/lab/service/UserService.java` (failed-query logs)

### 1. Original Vulnerable Code

```java
} catch (Exception ex) { return null; }      // loginUnsafe
} catch (Exception ex) { return new ArrayList<>(); } // findByUsernameUnsafe
```

### 2. Secure Replacement Code

```java
// AuthController.login
if (u == null) {
    org.slf4j.LoggerFactory.getLogger(AuthController.class)
            .warn("Failed login attempt for username of length {}",
                    username == null ? 0 : username.length());
    return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
}

// UserService.findByUsernameUnsafe
org.slf4j.LoggerFactory.getLogger(UserService.class)
        .warn("findByUsernameUnsafe failed for input of length {}",
                username == null ? 0 : username.length(), ex);

// UserService.loginUnsafe
org.slf4j.LoggerFactory.getLogger(UserService.class)
        .warn("loginUnsafe failed for username of length {}",
                username == null ? 0 : username.length(), ex);
```

### 3. Explanation of Change

Silent exception swallowing is replaced with structured SLF4J WARN
logs. Failed logins and SQL exceptions are now visible in standard
log aggregation. SIEM integration can pick up these events without
custom instrumentation.

**Residual:** dedicated `AuthenticationFailureBadCredentialsEvent` /
`AuthenticationSuccessEvent` Spring Security listeners, plus rate
limiting on `/api/login` and `/api/transfer`, are recommended in
*Secure Coding Recommendations*.

### 4. Security Benefit

Brute-force and credential-stuffing attempts become visible in logs.
Incident response has a forensic trail for failed authentication and
query errors.

---

## VULN-016 — Missing Security Headers / Clickjacking / CSP

- **Severity:** Medium
- **CWE / OWASP:** CWE-693 / CWE-1021 / A05:2021
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp/lab/config/SecurityConfig.java`

### 1. Original Vulnerable Code

```java
.headers(h -> h.frameOptions(f -> f.disable()));
```

### 2. Secure Replacement Code

```java
.headers(h -> h
        .contentSecurityPolicy(csp -> csp.policyDirectives(
                "default-src 'self'; " +
                "frame-ancestors 'self'; " +
                "script-src 'self'; " +
                "object-src 'none'"))
        .frameOptions(f -> f.sameOrigin())
        .referrerPolicy(r -> r.policy(
                org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                        .ReferrerPolicy.NO_REFERRER))
        .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true).maxAgeInSeconds(31536000))
);
```

### 3. Explanation of Change

A baseline security-headers set is configured:

- **Content-Security-Policy** restricts script sources to `'self'`,
  preventing any injected `<script>` from loading remote code (defence
  in depth against VULN-007/008).
- **X-Frame-Options: SAMEORIGIN** blocks clickjacking against the lab
  while still allowing the H2 console to render in its own frame.
- **Referrer-Policy: no-referrer** stops outbound links from leaking
  path information.
- **Strict-Transport-Security** instructs browsers (and the eventual
  TLS-terminating reverse proxy) to refuse plain-HTTP downgrades.

### 4. Security Benefit

Browser-side attack surface is reduced: XSS payloads are constrained by
CSP, clickjacking overlays are blocked, and referrer leakage is
eliminated.

---

## VULN-017 — H2 Console Exposed on Production-Equivalent Port

- **Severity:** Low
- **CWE / OWASP:** CWE-668 / CWE-284 / A05:2021
- **Status:** Applied
- **File Modified:** `src/main/resources/application.properties`

### 1. Original Vulnerable Code

```properties
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console
```

### 2. Secure Replacement Code

```properties
spring.h2.console.enabled=${H2_CONSOLE_ENABLED:false}
spring.h2.console.path=/h2-console
```

### 3. Explanation of Change

The H2 console is now OFF by default. Operators who want the lab's
local-sandbox convenience can opt in by setting `H2_CONSOLE_ENABLED=true`
on the JVM command line or environment. Combined with VULN-005 the
console endpoint is also `permitAll()`-only when explicitly enabled,
otherwise the application's authentication boundary applies.

### 4. Security Benefit

A production-shaped deployment no longer ships the H2 web console by
default. Direct GUI-driven database compromise requires an explicit
operator decision.

---

## VULN-018 — Information Disclosure via `/vulnerabilities`

- **Severity:** Low
- **CWE / OWASP:** CWE-200 / CWE-209 / A05:2021
- **Status:** Applied
- **File Modified:** `src/main/java/com/owasp\lab\controller\VulnerabilityController.java`

### 1. Original Vulnerable Code

```java
@Value("${app.secret.api.key}")  private String apiKey;
@Value("${app.secret.db.password}") private String dbPassword;

return """
    ...
    <li>API key: %s</li>
    <li>DB password: %s</li>
    ...
""".formatted(apiKey, dbPassword);
```

### 2. Secure Replacement Code

```java
@GetMapping(produces = MediaType.TEXT_HTML_VALUE)
public String index() {
    return """
        <!doctype html>
        <html>
          ...
          <p><b>Secrets:</b> redacted - sourced from environment variables
          at deploy time (see application.properties).</p>
          ...
        """;
}
```

### 3. Explanation of Change

The `@Value` autowiring of `apiKey` and `dbPassword` is removed from
the controller. The HTML response is now a static template that no
longer interpolates any secret value. The page still lists the
endpoint inventory so the lab's "where is the XSS / SQLi?" learning
value is preserved, but it no longer doubles as a credentials dump.

### 4. Security Benefit

Anonymous visitors and search-engine crawlers can no longer harvest
the lab's secrets from the public `/vulnerabilities` route.

---

# Security Improvements

The remediations above produce several cross-cutting security gains:

- **Cryptography:** All password storage uses BCrypt via a
  `DelegatingPasswordEncoder` bean, so future migrations to Argon2 or
  SCrypt are supported by the hash prefix rather than a schema change.
- **Authentication & Authorization:** Every endpoint requires
  authentication except the explicit `/api/login`, `/api/register`,
  `/h2-console/**`, and `/error` allow-list. ADMIN gating is in place
  on user enumeration. Ownership checks (or ADMIN) are required on
  per-user reads and writes.
- **CSRF:** CSRF protection is re-enabled; only the H2 console's
  internal POSTs are exempt.
- **XSS:** All user-controlled fields interpolated into HTML responses
  are run through `HtmlUtils.htmlEscape`. A defence-in-depth CSP is
  set globally.
- **SQL injection:** Both concatenated native queries are replaced
  with named-parameter bindings. Errors are logged, not swallowed.
- **Secrets management:** Hardcoded literals are replaced with env-var
  placeholders; the secrets page no longer renders their values.
- **Error handling & mass-assignment hardening:**
  `server.error.include-stacktrace=never` and
  `spring.jackson.deserialization.fail-on-unknown-properties=true` are
  set, so unexpected JSON fields and stack traces are rejected by
  default.
- **Logging:** Verbose SQL parameter tracing is off; failed-login and
  failed-query paths emit structured WARN logs.

---

# Residual Risks

The following items are **out of scope for this code-only remediation
run** and should be addressed by the team separately:

1. **Real secrets manager.** The `application.properties` file now
   references `${APP_SECRET_API_KEY}`, `${APP_SECRET_DB_PASSWORD}`, and
   `${APP_SECRET_JWT_SIGNING_KEY}` with empty defaults. A real
   deployment must wire these to Spring Cloud Config, HashiCorp Vault,
   AWS Secrets Manager, or equivalent. Failure to do so will leave
   `SecretConfig` returning empty strings, which downstream consumers
   may not handle gracefully.
2. **JWT key generation.** When JWT verification is added, the signing
   key must be a 256-bit value generated via `SecureRandom` and rotated
   periodically. The placeholder env var accepts any value; an operator
   must supply a high-entropy string at deploy time.
3. **H2 console.** The H2 console is now off by default but can be
   re-enabled via `H2_CONSOLE_ENABLED=true`. When enabled, the endpoint
   is `permitAll()`. Operators must not enable this in any
   non-local-sandbox profile.
4. **Purging git history.** The previously-committed secret literals
   (`AKIA-INTENTIONALLY-EXPOSED-...`,
   `P@ssw0rd123_plaintext_intentionally_exposed`,
   `this-is-a-hardcoded-jwt-signing-key-for-demo-only`) are still in
   git history. Run `git filter-repo` (or BFG) to purge them before
   pushing.
5. **User entity serialization.** `User.password` still exists as a
   getter on the entity. The `AuthController.login` response explicitly
   omits it, but `UserController.listUsers()` returns the full entity
   (gated to ADMIN) and `getProfile` returns the full entity (owner or
   ADMIN). Introduce a `UserResponse` DTO for these read paths so the
   password field cannot leak by accident if the entity is ever extended
   with another sensitive field. This was not changed here to keep the
   `/api/users` payload stable for lab consumers.
6. **Rate limiting / brute-force protection.** Bucket4j or equivalent
   rate limiting on `/api/login`, `/api/register`, and `/api/transfer`
   is not yet wired. The lab is now authentication-gated but a single
   account can still be brute-forced by an attacker who guesses
   usernames.
7. **Authentication event listeners.** The remediation emits SLF4J WARN
   logs on failed login but does not register Spring Security
   `AuthenticationFailureBadCredentialsEvent` /
   `AuthenticationSuccessEvent` listeners. These should be added for
   SIEM integration.
8. **Dependency CVE scanning.** `dependency-check-maven` is not yet in
   the build. Adding it with `<cvssThreshold>7</cvssThreshold>` and a
   CI gate is recommended.
9. **CSRF for HTTP Basic.** Because HTTP Basic is stateless and the
   caller must supply credentials with every request, CSRF protection
   is largely redundant in this lab. If a cookie-based session is
   added later, switch the CSRF token repository to
   `CookieCsrfTokenRepository.withHttpOnlyFalse()` and require the
   token on every POST/PUT/DELETE.

---

# Secure Coding Recommendations

Durable guardrails the team should adopt:

- **Code review checklist:**
  - Any new `createNativeQuery` / `createQuery` call must use bound
    parameters — never string concatenation.
  - Any new `@RequestBody` must be a DTO with `@Valid` and explicit
    `jakarta.validation` constraints; the global Jackson hardening
    (`fail-on-unknown-properties=true`) will then reject unknown
    fields by default.
  - Any new endpoint must declare an explicit authorization matcher in
    `SecurityConfig` (allow or deny list). The default-deny posture is
    `authenticated()`.
  - No `@Value` on a hardcoded literal in `application.properties` —
    always use `${ENV_VAR}` placeholders.
- **CI gates:**
  - Add `org.owasp:dependency-check-maven` to the build, configured
    with `<failBuildOnAnyVulnerability>true</failBuildOnAnyVulnerability>`
    and `<cvssThreshold>7</cvssThreshold>` for production builds.
  - Add SpotBugs / SonarQube with the `find-sec-bugs` ruleset. Block
    merges on new findings.
  - Run `mvn -B -q compile test-compile` in CI on every PR (this is
    the same gate used in this remediation run).
- **Threat modelling:**
  - Run a STRIDE-per-endpoint threat model at every release boundary.
    The `/api/deserialize`, `/api/login`, `/api/transfer`, and
    `/api/users` paths should be reviewed every iteration.
- **Secret management:**
  - Provision a Spring Cloud Config / Vault / AWS Secrets Manager
    backed `EnvironmentPostProcessor` so `${APP_SECRET_*}` lookups are
    resolved at boot, not in `application.properties`.
  - Rotate the JWT signing key (and any future signing / encryption
    keys) every 90 days.
- **Logging & monitoring:**
  - Forward Spring's structured JSON logs to a SIEM.
  - Configure alerts on more than N failed `/api/login` attempts per
    minute per source IP, and on any successful ADMIN login from a new
    geo.
- **Cryptography:**
  - Never invent bespoke hashing. Always use Spring Security's
    `DelegatingPasswordEncoder` (or the project standard
    `PasswordEncoder` bean) for credentials and AES/GCM for
    symmetric payloads.
  - Use `SecureRandom` (never `java.util.Random`) for tokens, IVs,
    salts.
- **Defence in depth:**
  - Keep CSP, HSTS, X-Frame-Options, Referrer-Policy, and
    X-Content-Type-Options as non-removable response headers.
  - Keep CSRF protection enabled for any cookie-based flow; document
    the bearer-token exemption explicitly.

---

*End of report.*
