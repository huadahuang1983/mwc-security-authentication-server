package com.reebake.mwc.security.config;

import com.reebake.mwc.security.controller.AuthenticationController;
import com.reebake.mwc.security.jwt.JwtProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableConfigurationProperties({JwtProperties.class})
@Import({AuthenticationManagerConfig.class, AuthServerCryptoConfig.class, AuthServerSecurityConfig.class, AuthServerFilterConfig.class,
        AuthServerProviderConfig.class, AuthenticationController.class})
public class AuthServerAutoConfiguration {
}
