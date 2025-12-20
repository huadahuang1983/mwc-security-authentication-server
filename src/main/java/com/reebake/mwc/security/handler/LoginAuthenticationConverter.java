package com.reebake.mwc.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.reebake.mwc.security.dto.LoginRequest;
import com.reebake.mwc.security.model.UsernameLoginAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

@RequiredArgsConstructor
public class LoginAuthenticationConverter implements AuthenticationConverter {
    private final ObjectMapper objectMapper;

    @Override
    @SneakyThrows
    public Authentication convert(HttpServletRequest request) {
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
        if(StringUtils.hasText(loginRequest.getUsername())) {
            return new UsernameLoginAuthenticationToken(loginRequest.getUsername(), loginRequest);
        }
        return null;
    }

}
