package com.iits.main.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

 
@Configuration
@EnableWebSecurity
//@EnableMethodSecurity(securedEnabled = true,prePostEnabled = true)
@EnableMethodSecurity
public class SecurityConfig {
    // Add security configurations if needed
}
