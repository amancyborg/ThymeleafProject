package com.example.thymeleaflogin.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenService {

    @Value("${security.ip-validation.enabled:true}")
    private boolean ipValidationEnabled;

    private final Map<String, TokenInfo> tokenStorage = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> refreshTokenStorage = new ConcurrentHashMap<>();

    public void storeToken(String token, String username, long expiresInSeconds) {
        LocalDateTime expirationTime = LocalDateTime.now().plusSeconds(expiresInSeconds);
        TokenInfo tokenInfo = new TokenInfo(username, expirationTime, null);
        tokenStorage.put(token, tokenInfo);
    }

    public void storeToken(String token, String username, long expiresInSeconds, String ipAddress) {
        LocalDateTime expirationTime = LocalDateTime.now().plusSeconds(expiresInSeconds);
        TokenInfo tokenInfo = new TokenInfo(username, expirationTime, ipAddress);
        tokenStorage.put(token, tokenInfo);
    }

    public void storeRefreshToken(String refreshToken, String username, long expiresInSeconds) {
        LocalDateTime expirationTime = LocalDateTime.now().plusSeconds(expiresInSeconds);
        TokenInfo tokenInfo = new TokenInfo(username, expirationTime, null);
        refreshTokenStorage.put(refreshToken, tokenInfo);
    }

    public void storeRefreshToken(String refreshToken, String username, long expiresInSeconds, String ipAddress) {
        LocalDateTime expirationTime = LocalDateTime.now().plusSeconds(expiresInSeconds);
        TokenInfo tokenInfo = new TokenInfo(username, expirationTime, ipAddress);
        refreshTokenStorage.put(refreshToken, tokenInfo);
    }

    public boolean isTokenValid(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        TokenInfo tokenInfo = tokenStorage.get(token);
        if (tokenInfo == null) {
            return false;
        }

        // Check if token has expired
        if (LocalDateTime.now().isAfter(tokenInfo.getExpirationTime())) {
            tokenStorage.remove(token);
            return false;
        }

        return true;
    }

    public boolean isRefreshTokenValid(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return false;
        }

        TokenInfo tokenInfo = refreshTokenStorage.get(refreshToken);
        if (tokenInfo == null) {
            return false;
        }

        if (LocalDateTime.now().isAfter(tokenInfo.getExpirationTime())) {
            refreshTokenStorage.remove(refreshToken);
            return false;
        }

        return true;
    }

    public boolean isTokenValidForIp(String token, String ipAddress) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        TokenInfo tokenInfo = tokenStorage.get(token);
        if (tokenInfo == null) {
            return false;
        }

        // Check if token has expired
        if (LocalDateTime.now().isAfter(tokenInfo.getExpirationTime())) {
            tokenStorage.remove(token);
            return false;
        }

        // Check IP address if IP validation is enabled and IP was stored during token creation
        if (ipValidationEnabled && tokenInfo.getIpAddress() != null && !tokenInfo.getIpAddress().equals(ipAddress)) {
            return false;
        }

        return true;
    }

    public boolean isTokenValidForUserAndIp(String token, String expectedUsername, String ipAddress) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        TokenInfo tokenInfo = tokenStorage.get(token);
        if (tokenInfo == null) {
            return false;
        }

        if (LocalDateTime.now().isAfter(tokenInfo.getExpirationTime())) {
            tokenStorage.remove(token);
            return false;
        }

        if (expectedUsername != null && !expectedUsername.equals(tokenInfo.getUsername())) {
            return false;
        }

        if (ipValidationEnabled && tokenInfo.getIpAddress() != null && !tokenInfo.getIpAddress().equals(ipAddress)) {
            return false;
        }

        return true;
    }

    public boolean isRefreshTokenValidForUserAndIp(String refreshToken, String expectedUsername, String ipAddress) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return false;
        }

        TokenInfo tokenInfo = refreshTokenStorage.get(refreshToken);
        if (tokenInfo == null) {
            return false;
        }

        if (LocalDateTime.now().isAfter(tokenInfo.getExpirationTime())) {
            refreshTokenStorage.remove(refreshToken);
            return false;
        }

        if (expectedUsername != null && !expectedUsername.equals(tokenInfo.getUsername())) {
            return false;
        }

        if (ipValidationEnabled && tokenInfo.getIpAddress() != null && !tokenInfo.getIpAddress().equals(ipAddress)) {
            return false;
        }

        return true;
    }

    public String getUsernameFromToken(String token) {
        TokenInfo tokenInfo = tokenStorage.get(token);
        if (tokenInfo != null && isTokenValid(token)) {
            return tokenInfo.getUsername();
        }
        return null;
    }

    public String getUsernameFromRefreshToken(String refreshToken) {
        TokenInfo tokenInfo = refreshTokenStorage.get(refreshToken);
        if (tokenInfo != null && isRefreshTokenValid(refreshToken)) {
            return tokenInfo.getUsername();
        }
        return null;
    }

    public void removeToken(String token) {
        tokenStorage.remove(token);
    }

    public void removeRefreshToken(String refreshToken) {
        refreshTokenStorage.remove(refreshToken);
    }

    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        tokenStorage.entrySet().removeIf(entry -> 
            now.isAfter(entry.getValue().getExpirationTime())
        );
        refreshTokenStorage.entrySet().removeIf(entry -> 
            now.isAfter(entry.getValue().getExpirationTime())
        );
    }

    private static class TokenInfo {
        private final String username;
        private final LocalDateTime expirationTime;
        private final String ipAddress;

        public TokenInfo(String username, LocalDateTime expirationTime, String ipAddress) {
            this.username = username;
            this.expirationTime = expirationTime;
            this.ipAddress = ipAddress;
        }

        public String getUsername() {
            return username;
        }

        public LocalDateTime getExpirationTime() {
            return expirationTime;
        }

        public String getIpAddress() {
            return ipAddress;
        }
    }
}
