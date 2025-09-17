package com.example.thymeleaflogin.interceptor;

import com.example.thymeleaflogin.model.AuthResponse;
import com.example.thymeleaflogin.service.AuthenticationService;
import com.example.thymeleaflogin.service.TokenService;
import com.example.thymeleaflogin.util.IpAddressUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.lang.NonNull;

@Component
public class TokenValidationInterceptor implements HandlerInterceptor {

    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private AuthenticationService authenticationService;

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Object handler) throws Exception {
        // Skip validation for login page and static resources
        String requestURI = request.getRequestURI();
        if (requestURI.equals("/login") || 
            requestURI.startsWith("/css/") || 
            requestURI.startsWith("/js/") || 
            requestURI.startsWith("/images/") ||
            requestURI.equals("/logout")) {
            return true;
        }

        HttpSession session = request.getSession(false);
        if (session == null) {
            // No session, redirect to login
            response.sendRedirect("/login?expired=true");
            return false;
        }

        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);
        
        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            // Try to refresh the access token using refresh token from cookie
            String refreshToken = getRefreshTokenFromCookie(request);
            if (refreshToken != null && username != null) {
                AuthResponse refreshResponse = authenticationService.refreshAccessToken(refreshToken, clientIpAddress, username);
                if (refreshResponse.isSuccess()) {
                    // Update session with new access token
                    session.setAttribute("authToken", refreshResponse.getToken());
                    
                    // Set new refresh token as cookie
                    String cookie = "refreshToken=" + refreshResponse.getRefreshToken() + "; Path=/; HttpOnly; Secure; SameSite=Lax";
                    response.addHeader("Set-Cookie", cookie);
                    
                    return true; // Continue with the request
                }
            }
            
            // Unable to refresh token, invalidate session and redirect to login
            session.invalidate();
            response.sendRedirect("/login?expired=true");
            return false;
        }

        return true;
    }
    
    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
