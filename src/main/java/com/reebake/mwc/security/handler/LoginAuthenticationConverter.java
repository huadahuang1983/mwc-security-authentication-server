package com.reebake.mwc.security.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.reebake.mwc.security.dto.LoginRequest;
import com.reebake.mwc.security.model.UsernameLoginAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

@RequiredArgsConstructor
public class LoginAuthenticationConverter implements AuthenticationConverter {
    private final ObjectMapper objectMapper;

    @Override
    @SneakyThrows
    public Authentication convert(HttpServletRequest request) {
        JsonNode root = objectMapper.readTree(request.getInputStream());
        if(root.has("username")) {
            String username = root.get("username").asText();
            String password = root.get("password").asText();

            LoginRequest loginRequest = new LoginRequest();
            loginRequest.setUsername(username);
            loginRequest.setPassword(password);
            return new UsernameLoginAuthenticationToken(loginRequest.getUsername(), loginRequest);
        }
        return null;
    }

}
