package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicSecurityConfig {

    @Bean
    SecurityFilterChain basicSecurityAuthentication(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.httpBasic()
                .and().authorizeHttpRequests()
                .anyRequest()
                .authenticated();

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
