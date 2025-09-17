package com.example.thymeleaflogin.controller;

import com.example.thymeleaflogin.model.AuthResponse;
import com.example.thymeleaflogin.model.LoginRequest;
import com.example.thymeleaflogin.service.AuthenticationService;
import com.example.thymeleaflogin.service.TokenService;
import com.example.thymeleaflogin.util.IpAddressUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(HttpServletRequest request,
                                                HttpServletResponse response,
                                                HttpSession session) {
        String clientIp = IpAddressUtil.getClientIpAddress(request);
        String expectedUsername = (String) session.getAttribute("username");

        String refreshToken = null;
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie c : request.getCookies()) {
                if ("refreshToken".equals(c.getName())) {
                    refreshToken = c.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(401).body(new AuthResponse(null, "Missing refresh token", false, 0));
        }

        AuthResponse refreshResponse = authenticationService.refreshAccessToken(refreshToken, clientIp, expectedUsername);
        if (!refreshResponse.isSuccess()) {
            // Clear cookie if invalid (Secure + SameSite=Lax)
            response.addHeader("Set-Cookie", "refreshToken=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
            return ResponseEntity.status(401).body(refreshResponse);
        }

        // Set new refresh token cookie
        if (refreshResponse.getRefreshToken() != null) {
            String cookie = "refreshToken=" + refreshResponse.getRefreshToken() + 
                "; Path=/; HttpOnly; Secure; SameSite=Lax";
            // Optionally: append "; Max-Age=" + refreshResponse.getRefreshExpiresIn()
            response.addHeader("Set-Cookie", cookie);
        }

        return ResponseEntity.ok(refreshResponse);
    }

    @GetMapping("/user-info")
    public ResponseEntity<Map<String, Object>> getUserInfo(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        // Check if token is valid and belongs to the session user and IP
        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Token expired, invalid, or IP mismatch");
            response.put("redirect", "/login");
            return ResponseEntity.status(401).body(response);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("username", username);
        response.put("token", token);
        response.put("sessionId", session.getId());
        response.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/ip-info")
    public ResponseEntity<Map<String, Object>> getIpInfo(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        // Check if token is valid and belongs to the session user and IP
        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Token expired, invalid, or IP mismatch");
            response.put("redirect", "/login");
            return ResponseEntity.status(401).body(response);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("username", username);
        response.put("currentIp", clientIpAddress);
        response.put("userAgent", request.getHeader("User-Agent"));
        response.put("timestamp", System.currentTimeMillis());
        response.put("message", "IP validation successful");

        return ResponseEntity.ok(response);
    }

    
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest loginRequest, HttpSession session, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            AuthResponse authResponse = authenticationService.authenticate(loginRequest);
            
            if (authResponse.isSuccess()) {
                // Store authentication data in session
                session.setAttribute("authToken", authResponse.getToken());
                session.setAttribute("username", loginRequest.getUsername());
                
                // Store token with user and IP information
                String clientIpAddress = IpAddressUtil.getClientIpAddress(request);
                tokenService.storeToken(authResponse.getToken(), loginRequest.getUsername(), 1800L, clientIpAddress);
                
                response.put("success", true);
                response.put("message", "Authentication successful");
                response.put("redirectUrl", "/dashboard");
            } else {
                response.put("success", false);
                response.put("message", authResponse.getMessage());
            }
            
            response.put("message", authResponse.getMessage());
            response.put("token", authResponse.getToken());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    @PostMapping("/shutdown")
    public ResponseEntity<Map<String, Object>> shutdownApplication(HttpSession session, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        // Verify authentication and authorization
        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            response.put("error", "Unauthorized access");
            return ResponseEntity.status(401).body(response);
        }

        // Additional security: Only allow admin user to shutdown
        if (!"admin".equals(username)) {
            response.put("error", "Insufficient privileges");
            return ResponseEntity.status(403).body(response);
        }

        response.put("success", true);
        response.put("message", "Application shutdown initiated");
        
        // Schedule shutdown after response is sent
        new Thread(() -> {
            try {
                Thread.sleep(1000); // Give time for response to be sent
                System.exit(0);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        return ResponseEntity.ok(response);
    }
}
