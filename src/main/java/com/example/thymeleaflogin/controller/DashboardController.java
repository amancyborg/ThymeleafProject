package com.example.thymeleaflogin.controller;

import com.example.thymeleaflogin.service.TokenService;
import com.example.thymeleaflogin.util.IpAddressUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class DashboardController {

    @Autowired
    private TokenService tokenService;

    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String fullname = (String) session.getAttribute("fullname");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        // Check if token is valid for the current user and IP
        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            return "redirect:/login?expired=true";
        }

        model.addAttribute("username", username);
        model.addAttribute("fullname", fullname);
        model.addAttribute("token", token);
        
        return "dashboard";
    }

    @GetMapping("/incidents")
    public String incidents(Model model, HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        // Check if token is valid for the current user and IP
        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            return "redirect:/login?expired=true";
        }

        // Add sample incidents data
        model.addAttribute("totalIncidents", 12);
        model.addAttribute("openIncidents", 5);
        model.addAttribute("inProgressIncidents", 4);
        model.addAttribute("resolvedIncidents", 3);
        
        return "incidents";
    }

}

