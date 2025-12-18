package com.reebake.mwc.security.config;

import com.reebake.mwc.security.handler.UsernameLoginAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AuthServerProviderConfig {

    @Bean
    public AuthenticationProvider usernameLoginAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        return new UsernameLoginAuthenticationProvider(userDetailsService, passwordEncoder);
    }

}
