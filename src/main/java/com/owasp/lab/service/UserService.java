package com.owasp.lab.service;

import com.owasp.lab.model.User;
import com.owasp.lab.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * User service - intentionally insecure for the OWASP learning lab.
 */
@Service
public class UserService {

    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // -----------------------------------------------------------------
    // REMEDIATION (OWASP A03:2021 - Injection: SQL Injection)
    //
    // Replaced raw concatenation with a parameterised native query
    // bound via :username.  User input is treated as a literal value
    // by Hibernate and can never alter the SQL structure.
    // -----------------------------------------------------------------
    @Transactional(readOnly = true)
    public List<User> findByUsernameUnsafe(String username) {
        try {
            return entityManager
                    .createNativeQuery(
                            "SELECT * FROM users WHERE username = :username",
                            User.class)
                    .setParameter("username", username)
                    .getResultList();
        } catch (Exception ex) {
            // REMEDIATION (A09:2021): log failed lookups rather than
            // silently swallowing exceptions.
            org.slf4j.LoggerFactory.getLogger(UserService.class)
                    .warn("findByUsernameUnsafe failed for input of length {}",
                            username == null ? 0 : username.length(), ex);
            return new ArrayList<>();
        }
    }

    // -----------------------------------------------------------------
    // REMEDIATION (OWASP A07:2021 - Broken Authentication):
    // Look the user up via parameterised SQL (no concatenation), then
    // compare the supplied password against the stored hash with a
    // constant-time BCrypt match.  Plaintext credentials are no longer
    // compared by the database.
    // -----------------------------------------------------------------
    public User loginUnsafe(String username, String password,
                            org.springframework.security.crypto.password.PasswordEncoder passwordEncoder) {
        try {
            List<User> rows = entityManager
                    .createNativeQuery(
                            "SELECT * FROM users WHERE username = :username",
                            User.class)
                    .setParameter("username", username)
                    .getResultList();
            if (rows.isEmpty()) {
                return null;
            }
            User candidate = rows.get(0);
            // Constant-time hash comparison; matches() also handles the
            // {bcrypt} prefix used by DelegatingPasswordEncoder.
            if (passwordEncoder.matches(password, candidate.getPassword())) {
                return candidate;
            }
            return null;
        } catch (Exception ex) {
            org.slf4j.LoggerFactory.getLogger(UserService.class)
                    .warn("loginUnsafe failed for username of length {}",
                            username == null ? 0 : username.length(), ex);
            return null;
        }
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    // VULNERABILITY (OWASP A01:2021 - Broken Access Control / IDOR):
    // Returns any user by ID without verifying the requester is allowed
    // to see them.
    public User findByIdUnsafe(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }
}
