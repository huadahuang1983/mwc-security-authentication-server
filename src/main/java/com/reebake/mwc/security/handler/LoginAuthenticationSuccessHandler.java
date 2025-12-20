package com.reebake.mwc.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.reebake.mwc.security.dto.AuthResponse;
import com.reebake.mwc.security.model.User;
import com.reebake.mwc.security.service.AuthenticationService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@RequiredArgsConstructor
public class LoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    protected final AuthenticationService authenticationService;
    protected final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();

        AuthResponse authResponse = authenticationService.generateAuthResponse(user);

        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(authResponse));
    }


}
