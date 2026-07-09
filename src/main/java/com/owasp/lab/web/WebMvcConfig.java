package com.owasp.lab.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Tiny MVC config: maps "/" to "/dashboard" so the lab's home URL is
 * the dashboard, not the raw API list.  Spring Security still controls
 * whether the redirect target is reachable.
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/", "/dashboard");
    }
}
