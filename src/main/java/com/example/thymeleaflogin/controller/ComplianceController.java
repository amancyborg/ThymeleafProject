package com.example.thymeleaflogin.controller;

import com.example.thymeleaflogin.service.TokenService;
import com.example.thymeleaflogin.util.IpAddressUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.*;
import java.util.stream.Collectors;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@RestController
@RequestMapping("/api/compliance")
public class ComplianceController {

    @Autowired
    private TokenService tokenService;
    
    // In-memory storage for email escalated items (in production, this would be in a database)
    private static final List<String> emailEscalatedItems = new ArrayList<>();

    @PostMapping("/search")
    public ResponseEntity<Map<String, Object>> searchComplianceItems(
            @RequestParam String query,
            HttpServletRequest request,
            HttpSession session) {
        
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

        // Get all compliance items from Total tab
        List<Map<String, Object>> allItems = getComplianceDataByTab("total");
        
        // Filter items based on search query
        List<Map<String, Object>> filteredItems = allItems.stream()
            .filter(item -> {
                String searchTerm = query.toLowerCase();
                return item.get("id").toString().toLowerCase().contains(searchTerm) ||
                       item.get("title").toString().toLowerCase().contains(searchTerm) ||
                       item.get("description").toString().toLowerCase().contains(searchTerm) ||
                       item.get("assignee").toString().toLowerCase().contains(searchTerm);
            })
            .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("items", filteredItems);
        response.put("total", filteredItems.size());
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/email-escalated/add")
    public ResponseEntity<Map<String, Object>> addToEmailEscalated(
            @RequestParam List<String> itemIds,
            HttpServletRequest request,
            HttpSession session) {
        
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

        // Add items to email escalated list (avoid duplicates)
        for (String itemId : itemIds) {
            if (!emailEscalatedItems.contains(itemId)) {
                emailEscalatedItems.add(itemId);
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Items added to email escalated list");
        response.put("totalCount", emailEscalatedItems.size());
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/email-escalated/remove")
    public ResponseEntity<Map<String, Object>> removeFromEmailEscalated(
            @RequestParam List<String> itemIds,
            HttpServletRequest request,
            HttpSession session) {
        
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

        // Remove items from email escalated list
        emailEscalatedItems.removeAll(itemIds);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Items removed from email escalated list");
        response.put("totalCount", emailEscalatedItems.size());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/email-escalated/list")
    public ResponseEntity<Map<String, Object>> getEmailEscalatedList(
            HttpServletRequest request,
            HttpSession session) {
        
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

        // Get full details for email escalated items
        List<Map<String, Object>> allItems = getComplianceDataByTab("total");
        List<Map<String, Object>> escalatedItems = allItems.stream()
            .filter(item -> emailEscalatedItems.contains(item.get("id").toString()))
            .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("items", escalatedItems);
        response.put("total", escalatedItems.size());
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/list")
    public ResponseEntity<Map<String, Object>> getComplianceList(
            @RequestParam(required = false) String tab,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) List<String> selectedItems,
            HttpServletRequest request,
            HttpSession session) {
        
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

        // Get compliance data based on tab
        List<Map<String, Object>> complianceItems;
        if ("email_escalated".equals(tab)) {
            // For email escalated tab, get items from the email escalated list
            List<Map<String, Object>> allItems = getComplianceDataByTab("total");
            complianceItems = allItems.stream()
                .filter(item -> emailEscalatedItems.contains(item.get("id").toString()))
                .collect(Collectors.toList());
        } else {
            complianceItems = getComplianceDataByTab(tab != null ? tab : "total");
        }
        
        // Apply search filter if provided
        if (search != null && !search.isEmpty()) {
            complianceItems = filterComplianceItems(complianceItems, search);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("items", complianceItems);
        response.put("total", complianceItems.size());
        response.put("tab", tab);
        response.put("username", username);
        response.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(response);
    }


    @PostMapping("/report")
    public ResponseEntity<String> generateComplianceReport(
            @RequestParam(required = false) List<String> selectedItems,
            @RequestParam(required = false) String reportType,
            @RequestParam(required = false) String selectionCriteria,
            HttpServletRequest request,
            HttpSession session) {
        
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            return ResponseEntity.status(401).body("Unauthorized access");
        }

        // Generate the HTML report
        String htmlReport = generateComplianceHtmlReport(selectedItems, username, reportType, selectionCriteria);
        
        return ResponseEntity.ok()
                .header("Content-Type", "text/html; charset=UTF-8")
                .header("Content-Disposition", "inline; filename=compliance-report.html")
                .body(htmlReport);
    }

    @PostMapping("/email-report")
    public ResponseEntity<String> generateEmailReport(
            @RequestParam(required = false) List<String> selectedItems,
            @RequestParam(required = false) String selectionCriteria,
            HttpServletRequest request,
            HttpSession session) {
        
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            return ResponseEntity.status(401).body("Unauthorized access");
        }

        // Generate the HTML email report with section-wise data
        String htmlReport = generateSectionWiseEmailReport(selectedItems, username, selectionCriteria);
        
        return ResponseEntity.ok()
                .header("Content-Type", "text/html; charset=UTF-8")
                .header("Content-Disposition", "inline; filename=compliance-email-report.html")
                .body(htmlReport);
    }

    @PostMapping("/stats")
    public ResponseEntity<Map<String, Object>> getComplianceStats(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Unauthorized access");
            return ResponseEntity.status(401).body(errorResponse);
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("total", 45);
        stats.put("escalated", 12);
        stats.put("nreca", 8);
        stats.put("email_escalated", 6);

        return ResponseEntity.ok(stats);
    }

    private List<Map<String, Object>> getComplianceDataByTab(String tab) {
        switch (tab.toLowerCase()) {
            case "escalated":
                return getEscalatedComplianceData();
            case "nreca":
                return getNRECAComplianceData();
            case "email_escalated":
                return getEmailEscalatedComplianceData();
            case "all":
            case "total":
            default:
                return getTotalComplianceData();
        }
    }

    private List<Map<String, Object>> getTotalComplianceData() {
        List<Map<String, Object>> items = new ArrayList<>();
        
        items.add(createComplianceItem("COMP001", "Data Privacy Audit", "High", "Escalated", "alice.johnson", "2024-01-15", 2, "total"));
        items.add(createComplianceItem("COMP002", "Security Policy Review", "Medium", "NRECA Review", "bob.smith", "2024-01-14", 3, "total"));
        items.add(createComplianceItem("COMP003", "GDPR Compliance Check", "High", "Escalated", "carol.davis", "2024-01-13", 4, "total"));
        items.add(createComplianceItem("COMP004", "Financial Audit Preparation", "Critical", "Email Escalated", "david.wilson", "2024-01-12", 5, "total"));
        items.add(createComplianceItem("COMP005", "NRECA Standards Verification", "Medium", "NRECA Review", "eve.brown", "2024-01-11", 6, "total"));
        items.add(createComplianceItem("COMP006", "Risk Assessment Update", "Low", "Escalated", "frank.miller", "2024-01-10", 7, "total"));
        items.add(createComplianceItem("COMP007", "Compliance Training Program", "Medium", "NRECA Review", "grace.taylor", "2024-01-09", 8, "total"));
        items.add(createComplianceItem("COMP008", "Incident Response Plan", "High", "Escalated", "henry.davis", "2024-01-08", 9, "total"));
        items.add(createComplianceItem("COMP009", "Cybersecurity Framework Review", "Critical", "Email Escalated", "iris.thomas", "2024-01-07", 10, "total"));
        items.add(createComplianceItem("COMP010", "NRECA Policy Alignment", "Medium", "NRECA Review", "jack.jackson", "2024-01-06", 11, "total"));
        items.add(createComplianceItem("COMP011", "SOX Compliance Review", "High", "Escalated", "karen.white", "2024-01-05", 12, "total"));
        items.add(createComplianceItem("COMP012", "Data Retention Policy", "Medium", "NRECA Review", "liam.brown", "2024-01-04", 13, "total"));
        items.add(createComplianceItem("COMP013", "Access Control Audit", "High", "Escalated", "mary.johnson", "2024-01-03", 14, "total"));
        items.add(createComplianceItem("COMP014", "Vendor Risk Assessment", "Medium", "NRECA Review", "noah.davis", "2024-01-02", 15, "total"));
        items.add(createComplianceItem("COMP015", "Business Continuity Plan", "Critical", "Email Escalated", "olivia.miller", "2024-01-01", 16, "total"));
        items.add(createComplianceItem("COMP016", "Privacy Impact Assessment", "High", "Escalated", "peter.wilson", "2023-12-31", 17, "total"));
        items.add(createComplianceItem("COMP017", "Regulatory Filing Review", "Medium", "NRECA Review", "quinn.taylor", "2023-12-30", 18, "total"));
        items.add(createComplianceItem("COMP018", "Third Party Risk Review", "Low", "Email Escalated", "rachel.anderson", "2023-12-29", 19, "total"));
        items.add(createComplianceItem("COMP019", "Information Security Policy", "High", "Escalated", "samuel.thomas", "2023-12-28", 20, "total"));
        items.add(createComplianceItem("COMP020", "Audit Trail Verification", "Medium", "NRECA Review", "tina.garcia", "2023-12-27", 21, "total"));
        items.add(createComplianceItem("COMP021", "Compliance Monitoring System", "Critical", "Email Escalated", "ursula.martinez", "2023-12-26", 22, "total"));
        items.add(createComplianceItem("COMP022", "Employee Background Checks", "Low", "NRECA Review", "victor.rodriguez", "2023-12-25", 23, "total"));
        items.add(createComplianceItem("COMP023", "Document Management Review", "Medium", "NRECA Review", "wendy.lopez", "2023-12-24", 24, "total"));
        items.add(createComplianceItem("COMP024", "Fraud Prevention Controls", "High", "Escalated", "xavier.hernandez", "2023-12-23", 25, "total"));
        items.add(createComplianceItem("COMP025", "Environmental Compliance", "Low", "NRECA Review", "yvonne.gonzalez", "2023-12-22", 26, "total"));
        items.add(createComplianceItem("COMP026", "Quality Management System", "Medium", "NRECA Review", "zachary.perez", "2023-12-21", 27, "total"));
        
        return items;
    }

    private List<Map<String, Object>> getEscalatedComplianceData() {
        List<Map<String, Object>> items = new ArrayList<>();
        
        items.add(createComplianceItem("COMP003", "GDPR Compliance Check", "High", "Escalated", "carol.davis", "2024-01-13", 4, "escalated"));
        items.add(createComplianceItem("COMP008", "Internal Control Testing", "High", "Escalated", "henry.anderson", "2024-01-08", 9, "escalated"));
        items.add(createComplianceItem("COMP015", "SOX Compliance Review", "Critical", "Escalated", "lisa.garcia", "2024-01-05", 12, "escalated"));
        items.add(createComplianceItem("COMP018", "Third Party Risk Assessment", "High", "Escalated", "mike.rodriguez", "2024-01-03", 14, "escalated"));
        
        return items;
    }

    private List<Map<String, Object>> getNRECAComplianceData() {
        List<Map<String, Object>> items = new ArrayList<>();
        
        items.add(createComplianceItem("COMP005", "NRECA Standards Verification", "Medium", "NRECA Review", "eve.brown", "2024-01-11", 6, "nreca"));
        items.add(createComplianceItem("COMP010", "NRECA Policy Alignment", "Medium", "NRECA Review", "jack.jackson", "2024-01-06", 11, "nreca"));
        items.add(createComplianceItem("COMP020", "NRECA Audit Preparation", "High", "NRECA Review", "nancy.lee", "2024-01-02", 15, "nreca"));
        items.add(createComplianceItem("COMP025", "NRECA Compliance Training", "Low", "NRECA Review", "oscar.martinez", "2023-12-28", 20, "nreca"));
        
        return items;
    }

    private List<Map<String, Object>> getEmailEscalatedComplianceData() {
        // Return items from the dynamic email escalated list
        List<Map<String, Object>> allItems = getTotalComplianceData();
        return allItems.stream()
            .filter(item -> emailEscalatedItems.contains(item.get("id").toString()))
            .collect(java.util.stream.Collectors.toList());
    }

    private Map<String, Object> createComplianceItem(String id, String title, String priority, String status, String assignee, String created, int age, String category) {
        Map<String, Object> item = new HashMap<>();
        item.put("id", id);
        item.put("title", title);
        item.put("description", "Compliance requirement for " + title.toLowerCase());
        item.put("priority", priority);
        item.put("status", status);
        item.put("assignee", formatAssignee(assignee));
        item.put("created", created);
        item.put("age", age);
        item.put("category", category);
        return item;
    }

    private List<Map<String, Object>> filterComplianceItems(List<Map<String, Object>> items, String search) {
        return items.stream()
                .filter(item -> {
                    String searchText = (item.get("id") + " " + item.get("title") + " " + item.get("assignee")).toLowerCase();
                    return searchText.contains(search.toLowerCase());
                })
                .collect(java.util.stream.Collectors.toList());
    }

    private String generateComplianceHtmlReport(List<String> selectedItems, String username, String reportType, String selectionCriteria) {
        // Get compliance data based on selection criteria
        List<Map<String, Object>> allItems;
        
        if (selectionCriteria != null && selectionCriteria.contains(",")) {
            // Multiple criteria selected - combine results from all
            String[] criteria = selectionCriteria.split(",");
            Set<Map<String, Object>> combinedItems = new HashSet<>();
            
            for (String criterion : criteria) {
                criterion = criterion.trim();
                if ("email_escalated".equals(criterion)) {
                    List<Map<String, Object>> emailItems = getTotalComplianceData().stream()
                        .filter(item -> emailEscalatedItems.contains(item.get("id").toString()))
                        .collect(java.util.stream.Collectors.toList());
                    combinedItems.addAll(emailItems);
                } else if (!"all".equals(criterion)) {
                    combinedItems.addAll(getComplianceDataByTab(criterion));
                }
            }
            allItems = new ArrayList<>(combinedItems);
        } else if ("email_escalated".equals(selectionCriteria)) {
            allItems = getTotalComplianceData().stream()
                .filter(item -> emailEscalatedItems.contains(item.get("id").toString()))
                .collect(java.util.stream.Collectors.toList());
        } else if (selectionCriteria != null && !selectionCriteria.isEmpty() && !"all".equals(selectionCriteria)) {
            allItems = getComplianceDataByTab(selectionCriteria);
        } else {
            allItems = getTotalComplianceData();
        }
        
        // Always use all items from the selected criteria (no individual item selection)
        List<Map<String, Object>> selectedComplianceItems = allItems;

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>");
        html.append("<html lang=\"en\">");
        html.append("<head>");
        html.append("<meta charset=\"UTF-8\">");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.append("<title>Compliance Report</title>");
        html.append("<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }");
        html.append(".header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }");
        html.append(".summary { background-color: #e9ecef; padding: 15px; border-radius: 8px; margin-bottom: 20px; }");
        html.append(".table { margin-top: 20px; background-color: white; }");
        html.append(".priority-critical { background-color: #dc3545; color: white; }");
        html.append(".priority-high { background-color: #fd7e14; color: white; }");
        html.append(".priority-medium { background-color: #ffc107; color: #212529; }");
        html.append(".priority-low { background-color: #28a745; color: white; }");
        html.append("</style>");
        html.append("</head>");
        html.append("<body>");
        
        // Header
        html.append("<div class=\"header\">");
        html.append("<h1><i class=\"fas fa-shield-alt\"></i> Compliance Report</h1>");
        html.append("<p class=\"mb-0\">Generated for: ").append(username).append(" | Date: ").append(LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd"))).append("</p>");
        html.append("</div>");
        
        // Summary
        html.append("<div class=\"summary\">");
        html.append("<h4>Report Summary</h4>");
        html.append("<p><strong>Total Selected Items:</strong> ").append(selectedComplianceItems.size()).append("</p>");
        html.append("<p><strong>Report Type:</strong> ").append(reportType != null ? reportType : "Standard Compliance Report").append("</p>");
        html.append("<p><strong>Selection Criteria:</strong> ").append(getSelectionCriteriaDisplayName(selectionCriteria)).append("</p>");
        html.append("</div>");
        
        // Items table
        html.append("<table class=\"table table-striped table-hover\">");
        html.append("<thead class=\"table-dark\">");
        html.append("<tr>");
        html.append("<th>ID</th>");
        html.append("<th>Title</th>");
        html.append("<th>Priority</th>");
        html.append("<th>Status</th>");
        html.append("<th>Assignee</th>");
        html.append("<th>Created</th>");
        html.append("<th>Age (Days)</th>");
        html.append("</tr>");
        html.append("</thead>");
        html.append("<tbody>");
        
        for (Map<String, Object> item : selectedComplianceItems) {
            html.append("<tr>");
            html.append("<td><strong>").append(item.get("id")).append("</strong></td>");
            html.append("<td>").append(item.get("title")).append("</td>");
            html.append("<td><span class=\"badge priority-").append(item.get("priority").toString().toLowerCase()).append("\">").append(item.get("priority")).append("</span></td>");
            html.append("<td>").append(item.get("status")).append("</td>");
            html.append("<td>").append(formatAssignee(item.get("assignee").toString())).append("</td>");
            html.append("<td>").append(item.get("created")).append("</td>");
            html.append("<td>").append(item.get("age")).append("</td>");
            html.append("</tr>");
        }
        
        html.append("</tbody>");
        html.append("</table>");
        html.append("</body>");
        html.append("</html>");
        
        return html.toString();
    }

    private String generateSectionWiseEmailReport(List<String> selectedItems, String username, String selectionCriteria) {
        // Get compliance data based on selection criteria
        List<Map<String, Object>> allItems;
        
        if (selectionCriteria != null && selectionCriteria.contains(",")) {
            // Multiple criteria selected - combine results from all
            String[] criteria = selectionCriteria.split(",");
            Set<Map<String, Object>> combinedItems = new HashSet<>();
            
            for (String criterion : criteria) {
                criterion = criterion.trim();
                if ("email_escalated".equals(criterion)) {
                    List<Map<String, Object>> emailItems = getTotalComplianceData().stream()
                        .filter(item -> emailEscalatedItems.contains(item.get("id").toString()))
                        .collect(java.util.stream.Collectors.toList());
                    combinedItems.addAll(emailItems);
                } else if (!"all".equals(criterion)) {
                    combinedItems.addAll(getComplianceDataByTab(criterion));
                }
            }
            allItems = new ArrayList<>(combinedItems);
        } else if ("email_escalated".equals(selectionCriteria)) {
            allItems = getTotalComplianceData().stream()
                .filter(item -> emailEscalatedItems.contains(item.get("id").toString()))
                .collect(java.util.stream.Collectors.toList());
        } else if (selectionCriteria != null && !selectionCriteria.isEmpty() && !"all".equals(selectionCriteria)) {
            allItems = getComplianceDataByTab(selectionCriteria);
        } else {
            allItems = getTotalComplianceData();
        }
        
        // Always use all items from the selected criteria (no individual item selection)
        List<Map<String, Object>> selectedComplianceItems = allItems;

        // Group items by category
        Map<String, List<Map<String, Object>>> itemsByCategory = selectedComplianceItems.stream()
                .collect(java.util.stream.Collectors.groupingBy(item -> item.get("category").toString()));

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>");
        html.append("<html lang=\"en\">");
        html.append("<head>");
        html.append("<meta charset=\"UTF-8\">");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.append("<title>Compliance Email Report</title>");
        html.append("<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }");
        html.append(".header { background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }");
        html.append(".common-comment { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; }");
        html.append(".section { background-color: white; margin-bottom: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
        html.append(".section-header { background-color: #6c757d; color: white; padding: 15px; font-weight: bold; }");
        html.append(".table { margin: 0; }");
        html.append(".priority-critical { background-color: #dc3545; color: white; }");
        html.append(".priority-high { background-color: #fd7e14; color: white; }");
        html.append(".priority-medium { background-color: #ffc107; color: #212529; }");
        html.append(".priority-low { background-color: #28a745; color: white; }");
        html.append("</style>");
        html.append("</head>");
        html.append("<body>");
        
        // Header
        html.append("<div class=\"header\">");
        html.append("<h1><i class=\"fas fa-envelope\"></i> Compliance Email Report</h1>");
        html.append("<p class=\"mb-0\">Generated for: ").append(username).append(" | Date: ").append(LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd"))).append("</p>");
        html.append("</div>");
        
        // Common start comment
        html.append("<div class=\"common-comment\">");
        html.append("<h5><i class=\"fas fa-info-circle\"></i> Report Overview</h5>");
        html.append("<p>This compliance report provides a comprehensive overview of selected compliance items organized by category. ");
        html.append("Each section contains detailed information about compliance activities, their current status, priority levels, and assigned personnel. ");
        html.append("Please review each section carefully and take appropriate action where necessary.</p>");
        html.append("<p><strong>Total Items in Report:</strong> ").append(selectedComplianceItems.size()).append("</p>");
        html.append("</div>");
        
        // Section-wise data
        String[] categoryOrder = {"total", "escalated", "nreca", "email_escalated"};
        String[] categoryTitles = {"Total Compliance Items", "Escalated Items", "NRECA Items", "Email Escalated Items"};
        
        for (int i = 0; i < categoryOrder.length; i++) {
            String category = categoryOrder[i];
            String categoryTitle = categoryTitles[i];
            
            if (itemsByCategory.containsKey(category)) {
                List<Map<String, Object>> categoryItems = itemsByCategory.get(category);
                
                html.append("<div class=\"section\">");
                html.append("<div class=\"section-header\">");
                html.append("<h4>").append(categoryTitle).append(" (").append(categoryItems.size()).append(" items)</h4>");
                html.append("</div>");
                
                html.append("<table class=\"table table-striped\">");
                html.append("<thead class=\"table-light\">");
                html.append("<tr>");
                html.append("<th>ID</th>");
                html.append("<th>Title</th>");
                html.append("<th>Priority</th>");
                html.append("<th>Status</th>");
                html.append("<th>Assignee</th>");
                html.append("<th>Age (Days)</th>");
                html.append("</tr>");
                html.append("</thead>");
                html.append("<tbody>");
                
                for (Map<String, Object> item : categoryItems) {
                    html.append("<tr>");
                    html.append("<td><strong>").append(item.get("id")).append("</strong></td>");
                    html.append("<td>").append(item.get("title")).append("</td>");
                    html.append("<td><span class=\"badge priority-").append(item.get("priority").toString().toLowerCase()).append("\">").append(item.get("priority")).append("</span></td>");
                    html.append("<td>").append(item.get("status")).append("</td>");
                    html.append("<td>").append(formatAssignee(item.get("assignee").toString())).append("</td>");
                    html.append("<td>").append(item.get("age")).append("</td>");
                    html.append("</tr>");
                }
                
                html.append("</tbody>");
                html.append("</table>");
                html.append("</div>");
            }
        }
        
        // Footer
        html.append("<div class=\"mt-4 text-center text-muted\">");
        html.append("<p><small>This report was automatically generated by the Compliance Management System.</small></p>");
        html.append("</div>");
        
        html.append("</body>");
        html.append("</html>");
        
        return html.toString();
    }

    private String formatAssignee(String assignee) {
        String[] words = assignee.replace(".", " ").split("\\s+");
        StringBuilder result = new StringBuilder();
        for (String word : words) {
            if (word.length() > 0) {
                result.append(Character.toUpperCase(word.charAt(0)))
                      .append(word.substring(1).toLowerCase())
                      .append(" ");
            }
        }
        return result.toString().trim();
    }

    private String getSelectionCriteriaDisplayName(String selectionCriteria) {
        if (selectionCriteria == null || selectionCriteria.isEmpty() || "all".equals(selectionCriteria)) {
            return "All Items";
        }
        switch (selectionCriteria.toLowerCase()) {
            case "escalated":
                return "Escalated Items";
            case "nreca":
                return "NRECA Items";
            case "email_escalated":
                return "Email Escalated Items";
            default:
                return "Custom Selection";
        }
    }
}
