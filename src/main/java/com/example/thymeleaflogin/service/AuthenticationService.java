package com.example.thymeleaflogin.service;

import com.example.thymeleaflogin.model.AuthResponse;
import com.example.thymeleaflogin.model.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class AuthenticationService {

    @Value("${external.api.base-url}")
    private String externalApiBaseUrl;

    @Value("${external.api.timeout}")
    private int timeout;

    @Value("${security.tokens.access-token-expiry}")
    private long accessTokenExpiry;

    @Value("${security.tokens.refresh-token-expiry}")
    private long refreshTokenExpiry;

    private WebClient webClient;
    private final TokenService tokenService;

    @Autowired
    public AuthenticationService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostConstruct
    public void init() {
        this.webClient = WebClient.builder()
                .baseUrl(externalApiBaseUrl)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    public AuthResponse authenticate(LoginRequest loginRequest) {
        return authenticate(loginRequest, null);
    }

    public AuthResponse authenticate(LoginRequest loginRequest, String ipAddress) {
        try {
            // Create base64 encoded credentials
            String credentials = loginRequest.getUsername() + ":" + loginRequest.getPassword();
            String encodedCredentials = Base64.getEncoder()
                    .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            String authorization = "Basic " + encodedCredentials;

            // Make API call with base64 encoded credentials
            String response = webClient.get()
                    .uri("/posts/1")
                    .header(HttpHeaders.AUTHORIZATION, authorization)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofMillis(timeout))
                    .block();

            if (response != null && !response.isEmpty()) {
                // Generate tokens on successful API response
                String accessToken = generateToken();
                String refreshToken = generateRefreshToken();
                long accessExpiresIn = accessTokenExpiry;
                long refreshExpiresIn = refreshTokenExpiry;

                // Store tokens with authorization and optional IP
                tokenService.storeToken(accessToken, loginRequest.getUsername(), accessExpiresIn, ipAddress, authorization);
                tokenService.storeRefreshToken(refreshToken, loginRequest.getUsername(), refreshExpiresIn, ipAddress, authorization);

                // Attempt to parse fullname from external API response JSON
                String fullname = null;
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    JsonNode node = mapper.readTree(response);
                    if (node != null) {
                        if (node.hasNonNull("fullname")) {
                            fullname = node.get("fullname").asText();
                        } else if (node.hasNonNull("fullName")) {
                            fullname = node.get("fullName").asText();
                        } else if (node.hasNonNull("name")) {
                            fullname = node.get("name").asText();
                        }
                    }
                } catch (Exception ignored) {
                    // Ignore parsing errors and fallback to username
                }
                if (fullname == null || fullname.isBlank()) {
                    fullname = loginRequest.getUsername();
                }

                AuthResponse auth = new AuthResponse(accessToken, accessExpiresIn, refreshToken, refreshExpiresIn, "Authentication successful", true);
                auth.setFullname(fullname);
                return auth;
            } else {
                return new AuthResponse(null, "Invalid credentials", false, 0);
            }

        } catch (WebClientResponseException e) {
            if (e.getStatusCode().value() == 401) {
                return new AuthResponse(null, "Invalid credentials", false, 0);
            } else {
                return new AuthResponse(null, "Authentication service unavailable", false, 0);
            }
        } catch (Exception e) {
            return new AuthResponse(null, "Authentication failed: " + e.getMessage(), false, 0);
        }
    }

    private String generateToken() {
        return "token_" + UUID.randomUUID().toString().replace("-", "");
    }

    private String generateRefreshToken() {
        return "refresh_" + UUID.randomUUID().toString().replace("-", "");
    }

    public boolean validateToken(String token) {
        return tokenService.isTokenValid(token);
    }

    public String getUsernameFromToken(String token) {
        return tokenService.getUsernameFromToken(token);
    }

    public AuthResponse refreshAccessToken(String refreshToken, String ipAddress) {
        boolean valid = tokenService.isRefreshTokenValid(refreshToken);
        if (!valid) {
            return new AuthResponse(null, "Invalid or expired refresh token", false, 0);
        }

        String username = tokenService.getUsernameFromRefreshToken(refreshToken);
        if (username == null) {
            return new AuthResponse(null, "Invalid refresh token", false, 0);
        }

        // Carry over authorization from the existing refresh token
        String authorization = tokenService.getAuthorizationFromRefreshToken(refreshToken);

        // Issue new access token and rotate refresh token
        String newAccessToken = generateToken();
        String newRefreshToken = generateRefreshToken();
        long accessExpiresIn = accessTokenExpiry;
        long refreshExpiresIn = refreshTokenExpiry;
        tokenService.storeToken(newAccessToken, username, accessExpiresIn, ipAddress, authorization);
        tokenService.storeRefreshToken(newRefreshToken, username, refreshExpiresIn, ipAddress, authorization);
        tokenService.removeRefreshToken(refreshToken);

        return new AuthResponse(newAccessToken, accessExpiresIn, newRefreshToken, refreshExpiresIn, "Token refreshed", true);
    }

    public AuthResponse refreshAccessToken(String refreshToken, String ipAddress, String expectedUsername) {
        boolean valid = tokenService.isRefreshTokenValidForUserAndIp(refreshToken, expectedUsername, ipAddress);
        if (!valid) {
            return new AuthResponse(null, "Invalid or expired refresh token", false, 0);
        }

        String username = tokenService.getUsernameFromRefreshToken(refreshToken);

        // Carry over authorization from the existing refresh token
        String authorization = tokenService.getAuthorizationFromRefreshToken(refreshToken);

        String newAccessToken = generateToken();
        String newRefreshToken = generateRefreshToken();
        long accessExpiresIn = accessTokenExpiry;
        long refreshExpiresIn = refreshTokenExpiry;
        tokenService.storeToken(newAccessToken, username, accessExpiresIn, ipAddress, authorization);
        tokenService.storeRefreshToken(newRefreshToken, username, refreshExpiresIn, ipAddress, authorization);
        tokenService.removeRefreshToken(refreshToken);

        return new AuthResponse(newAccessToken, accessExpiresIn, newRefreshToken, refreshExpiresIn, "Token refreshed", true);
    }
}
