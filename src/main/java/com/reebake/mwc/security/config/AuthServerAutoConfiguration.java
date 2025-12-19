package com.reebake.mwc.security.config;

import com.reebake.mwc.security.captcha.CaptchaProperties;
import com.reebake.mwc.security.captcha.config.CaptchaConfig;
import com.reebake.mwc.security.controller.AuthenticationController;
import com.reebake.mwc.security.jwt.JwtProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableConfigurationProperties({JwtProperties.class, CaptchaProperties.class})
@Import({AuthenticationManagerConfig.class, AuthServerCryptoConfig.class, AuthServerSecurityConfig.class, AuthServerFilterConfig.class,
        AuthServerProviderConfig.class, AuthenticationController.class, CaptchaConfig.class})
public class AuthServerAutoConfiguration {
}
