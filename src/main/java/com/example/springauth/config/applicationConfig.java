package com.example.springauth.config;

import com.example.springauth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor
public class applicationConfig {

    private final UserRepository userRepository;


    /**
     * Defines a bean for user details service.
     * This method creates an instance of UserDetailsService, which is used by Spring Security
     * to load user details during authentication.
     *
     * @return An instance of UserDetailsService.
     */
    @Bean
    public UserDetailsService userDetailsService(){
        // Lambda expression to implement UserDetailsService interface
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
