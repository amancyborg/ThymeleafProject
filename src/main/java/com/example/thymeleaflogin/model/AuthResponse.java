package com.example.thymeleaflogin.model;

public class AuthResponse {
    
    private String token;
    private String refreshToken;
    private String message;
    private boolean success;
    private long expiresIn;
    private long refreshExpiresIn;
    private String fullname;

    public AuthResponse() {}

    public AuthResponse(String token, String message, boolean success, long expiresIn) {
        this.token = token;
        this.message = message;
        this.success = success;
        this.expiresIn = expiresIn;
    }

    public AuthResponse(String token, long expiresIn, String refreshToken, long refreshExpiresIn, String message, boolean success) {
        this.token = token;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.refreshExpiresIn = refreshExpiresIn;
        this.message = message;
        this.success = success;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public long getRefreshExpiresIn() {
        return refreshExpiresIn;
    }

    public void setRefreshExpiresIn(long refreshExpiresIn) {
        this.refreshExpiresIn = refreshExpiresIn;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }
}


