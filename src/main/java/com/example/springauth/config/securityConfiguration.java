package com.example.springauth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class securityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    /**
     * Configures the security filter chain for HTTP requests.
     *
     * @param http The HttpSecurity object to configure security settings.
     * @return A SecurityFilterChain configured with the specified settings.
     * @throws Exception If an error occurs during configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection
                .authorizeHttpRequests(auth -> auth // Authorize HTTP requests
                        .requestMatchers("/api/v1/auth/**").permitAll() // Permit access to /api/v1/auth/** endpoints
                        .anyRequest().authenticated() // Require authentication for any other request
                )
                .sessionManagement(session -> session // Configure session management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Use stateless session management
                )
                .authenticationProvider(authenticationProvider) // Set the authentication provider
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) // Add JWT authentication filter before UsernamePasswordAuthenticationFilter
                .build(); // Build and return the SecurityFilterChain
    }
}
