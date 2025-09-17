package com.example.thymeleaflogin.security;

import com.example.thymeleaflogin.model.AuthResponse;
import com.example.thymeleaflogin.model.LoginRequest;
import com.example.thymeleaflogin.service.AuthenticationService;
import com.example.thymeleaflogin.util.IpAddressUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {


    @Autowired
    private AuthenticationService authenticationService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // Get IP address from current request context
        String clientIpAddress = getClientIpAddress();
        

        LoginRequest loginRequest = new LoginRequest(username, password);
        AuthResponse authResponse = authenticationService.authenticate(loginRequest, clientIpAddress);

        if (authResponse.isSuccess()) {
            // Store AuthResponse in authentication details for later use (to access refresh token)
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                username, 
                password, 
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
            );
            authToken.setDetails(authResponse);
            
            return authToken;
        } else {
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();
            return IpAddressUtil.getClientIpAddress(request);
        } catch (Exception e) {
            // Could not get client IP address
            return "unknown";
        }
    }
}

