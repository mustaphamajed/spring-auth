package com.example.springauth.config;

import com.example.springauth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    /**
     * Defines an authentication provider bean.
     * This method configures and returns an instance of DaoAuthenticationProvider,
     * which uses the provided userDetailsService for retrieving user details
     * and the BCryptPasswordEncoder for encoding passwords.
     *
     * @return An instance of AuthenticationProvider configured for DAO-based authentication.
     */
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    /**
     * Defines a password encoder bean.
     * This method configures and returns an instance of BCryptPasswordEncoder,
     * which is a password encoder implementation that uses bcrypt hashing.
     *
     * @return An instance of PasswordEncoder configured to use BCrypt hashing.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * Defines an AuthenticationManager bean.
     * This method creates and returns an instance of AuthenticationManager
     * by retrieving it from the provided AuthenticationConfiguration.
     *
     * @param authenticationConfiguration An AuthenticationConfiguration instance used to retrieve the AuthenticationManager.
     * @return An instance of AuthenticationManager.
     * @throws Exception If an error occurs while retrieving the AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


}
