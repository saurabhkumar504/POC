package com.owasp.lab.config;

import com.owasp.lab.model.Comment;
import com.owasp.lab.model.Product;
import com.owasp.lab.model.User;
import com.owasp.lab.repository.CommentRepository;
import com.owasp.lab.repository.ProductRepository;
import com.owasp.lab.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Seeds the H2 in-memory database with test data on application start.
 *
 * REMEDIATION (OWASP A02:2021 - Cryptographic Failures /
 *              OWASP A07:2021 - Identification and Authentication Failures):
 * Seed user passwords are hashed via the configured {@link PasswordEncoder}
 * (BCrypt by default) before being persisted.  Plaintext credentials never
 * reach the database.
 */
@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner seed(UserRepository userRepository,
                           ProductRepository productRepository,
                           CommentRepository commentRepository,
                           PasswordEncoder passwordEncoder) {
        return args -> {
            userRepository.save(new User("alice", passwordEncoder.encode("alice123"),
                    "alice@example.com", "USER",  1000.0));
            userRepository.save(new User("bob",   passwordEncoder.encode("bob123"),
                    "bob@example.com",   "USER",   500.0));
            userRepository.save(new User("admin", passwordEncoder.encode("admin123"),
                    "admin@example.com", "ADMIN", 9999.0));

            productRepository.save(new Product("Laptop",   "16GB RAM, 512GB SSD",  1299.99));
            productRepository.save(new Product("Mouse",    "Wireless",              19.99));
            productRepository.save(new Product("Keyboard", "Mechanical, RGB",      89.99));

            // Pre-seeded comment used by the XSS demo.
            commentRepository.save(new Comment("system", "Welcome to the lab!"));
        };
    }
}
