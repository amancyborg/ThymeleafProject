package com.example.thymeleaflogin.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class    IpAddressUtil {

    /**
     * Extracts the real IP address from the HTTP request.
     * This method checks various headers that might contain the real IP
     * when the application is behind a proxy or load balancer.
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        // For development testing - check if there's a test IP header
        String testIp = request.getHeader("X-Test-Client-IP");
        if (testIp != null && !testIp.isEmpty() && isValidIp(testIp)) {
            return testIp;
        }
        
        // Check X-Forwarded-For header first
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            // X-Forwarded-For can contain multiple IPs, take the first one
            String ip = xForwardedFor.split(",")[0].trim();
            if (isValidIp(ip)) {
                return ip;
            }
        }

        // Check X-Real-IP header
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp) && isValidIp(xRealIp)) {
            return xRealIp;
        }

        // Check other forwarding headers
        String xForwarded = request.getHeader("X-Forwarded");
        if (xForwarded != null && !xForwarded.isEmpty() && !"unknown".equalsIgnoreCase(xForwarded) && isValidIp(xForwarded)) {
            return xForwarded;
        }

        String forwardedFor = request.getHeader("Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(forwardedFor) && isValidIp(forwardedFor)) {
            return forwardedFor;
        }

        String forwarded = request.getHeader("Forwarded");
        if (forwarded != null && !forwarded.isEmpty() && !"unknown".equalsIgnoreCase(forwarded) && isValidIp(forwarded)) {
            return forwarded;
        }

        // Fall back to remote address
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr != null && !remoteAddr.isEmpty() && !"unknown".equalsIgnoreCase(remoteAddr)) {
            // Convert IPv6 localhost to IPv4 for consistency
            if (remoteAddr.equals("0:0:0:0:0:0:0:1")) {
                return "127.0.0.1"; // Convert IPv6 localhost to IPv4
            }
            if (isValidIp(remoteAddr)) {
                return remoteAddr;
            }
        }

        // For localhost development, return IPv4 localhost
        if (remoteAddr == null || remoteAddr.isEmpty()) {
            return "127.0.0.1"; // Default to IPv4 localhost for development
        }

        // Last resort
        return "unknown";
    }

    /**
     * Simple IP validation - checks if the string looks like an IP address
     */
    private static boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        
        // Basic validation - should contain dots (IPv4) or colons (IPv6)
        return ip.contains(".") || ip.contains(":") || "localhost".equals(ip);
    }

    /**
     * Checks if two IP addresses are the same, considering IPv4 and IPv6 formats
     */
    public static boolean isSameIpAddress(String ip1, String ip2) {
        if (ip1 == null || ip2 == null) {
            return false;
        }
        
        // Normalize both IPs to IPv4 format for comparison
        String normalizedIp1 = normalizeToIPv4(ip1);
        String normalizedIp2 = normalizeToIPv4(ip2);
        
        return normalizedIp1.equals(normalizedIp2);
    }
    
    /**
     * Normalizes IP addresses to IPv4 format when possible
     */
    private static String normalizeToIPv4(String ip) {
        if (ip == null) {
            return "unknown";
        }
        
        // Convert common IPv6 localhost representations to IPv4
        if (ip.equals("0:0:0:0:0:0:0:1") || ip.equals("::1")) {
            return "127.0.0.1";
        }
        
        // Return as-is if already IPv4 or other format
        return ip;
    }
}
