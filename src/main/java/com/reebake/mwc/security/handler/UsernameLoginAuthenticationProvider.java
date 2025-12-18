package com.reebake.mwc.security.handler;

import com.reebake.mwc.security.dto.LoginRequest;
import com.reebake.mwc.security.model.User;
import com.reebake.mwc.security.model.UsernameLoginAuthenticationToken;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Setter
@RequiredArgsConstructor
public class UsernameLoginAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private UserDetailsChecker userDetailsChecker = new DefaultPreAuthenticationChecks();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginRequest loginRequest = (LoginRequest) authentication.getCredentials();
        String username = loginRequest.getUsername();
        User user = (User) userDetailsService.loadUserByUsername(username);

        String rawPassword = loginRequest.getPassword();
        if(!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsException("password not matches");
        }
        userDetailsChecker.check(user);

        return UsernameLoginAuthenticationToken.authenticated(user, loginRequest, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernameLoginAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
