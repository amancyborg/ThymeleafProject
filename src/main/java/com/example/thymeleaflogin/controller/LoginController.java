package com.example.thymeleaflogin.controller;

import com.example.thymeleaflogin.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;

@Controller
public class LoginController {

    @Autowired
    private TokenService tokenService;

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                       @RequestParam(value = "logout", required = false) String logout,
                       Model model, HttpSession session) {
        
        // Check if user is already authenticated
        String token = (String) session.getAttribute("authToken");
        if (token != null && tokenService.isTokenValid(token)) {
            return "redirect:/dashboard";
        }

        if (error != null) {
            model.addAttribute("error", "Invalid username or password");
        }

        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully");
        }

        return "login";
    }
}

