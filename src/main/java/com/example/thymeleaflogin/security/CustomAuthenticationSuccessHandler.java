package com.example.thymeleaflogin.security;

import com.example.thymeleaflogin.model.AuthResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Value("${security.session.timeout}")
    private int sessionTimeout;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
        
        // Get tokens from authentication details
        AuthResponse auth = (AuthResponse) authentication.getDetails();
        String token = auth.getToken();
        String refreshToken = auth.getRefreshToken();
        String username = authentication.getName();
        
        
        // Store token in session
        HttpSession session = request.getSession();
        session.setAttribute("authToken", token);
        session.setAttribute("username", username);
        
        // Set session timeout from configuration
        session.setMaxInactiveInterval(sessionTimeout);
        
        // Set refresh token as HttpOnly, Secure cookie with SameSite=Lax
        if (refreshToken != null) {
            String cookie = "refreshToken=" + refreshToken + "; Path=/; HttpOnly; Secure; SameSite=Lax";
            response.addHeader("Set-Cookie", cookie);
        }

        // Redirect to dashboard
        response.sendRedirect("/dashboard");
    }
}
