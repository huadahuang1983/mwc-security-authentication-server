package com.reebake.mwc.security.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "mwc.jwt")
@Getter
@Setter
public class JwtProperties {

    private String issuer = "mwc-security";
    private long expirationTimeInMinutes = 30;

}