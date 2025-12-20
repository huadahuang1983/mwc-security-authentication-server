package com.reebake.mwc.security.controller;

import com.reebake.mwc.security.captcha.CaptchaService;
import com.reebake.mwc.security.captcha.CaptchaProperties;
import com.reebake.mwc.security.dto.AuthResponse;
import com.reebake.mwc.security.service.AuthenticationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final CaptchaService captchaService;
    private final CaptchaProperties captchaProperties;

    public AuthenticationController(AuthenticationService authenticationService, CaptchaService captchaService, CaptchaProperties captchaProperties) {
        this.authenticationService = authenticationService;
        this.captchaService = captchaService;
        this.captchaProperties = captchaProperties;
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestHeader("Refresh-Token") String refreshToken) {
        AuthResponse authResponse = authenticationService.refreshToken(refreshToken);
        return ResponseEntity.ok(authResponse);
    }

    @GetMapping("/captcha")
    public ResponseEntity<byte[]> getCaptcha() throws IOException {
        if (!captchaProperties.isEnabled()) {
            return ResponseEntity.status(403).build();
        }
        
        var captchaInfo = captchaService.generateCaptcha();
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_JPEG);
        headers.set("Captcha-ID", captchaInfo.captchaId());
        
        return ResponseEntity.ok()
                .headers(headers)
                .body(captchaInfo.captchaImage());
    }

}