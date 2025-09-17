package com.example.thymeleaflogin.scheduler;

import com.example.thymeleaflogin.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class TokenCleanupScheduler {

    @Autowired
    private TokenService tokenService;

    @Scheduled(fixedRateString = "${security.scheduler.token-cleanup-interval}")
    public void cleanupExpiredTokens() {
        tokenService.cleanupExpiredTokens();
    }
}
