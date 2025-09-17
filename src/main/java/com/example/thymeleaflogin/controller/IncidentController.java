package com.example.thymeleaflogin.controller;

import com.example.thymeleaflogin.service.TokenService;
import com.example.thymeleaflogin.util.IpAddressUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {

    @Autowired
    private TokenService tokenService;

    @PostMapping("/report")
    public ResponseEntity<String> getIncidentsReport(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String ageing,
            @RequestParam(required = false) String priority,
            @RequestParam(required = false) String assignee,
            @RequestParam(required = false) String search,
            HttpServletRequest request,
            HttpSession session) {
        
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        // Check if token is valid and belongs to the session user and IP
        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            return ResponseEntity.status(401).body("Unauthorized access");
        }

        // Generate the HTML report
        String htmlReport = generateIncidentsReport(status, ageing, priority, assignee, search, username);
        
        return ResponseEntity.ok()
                .header("Content-Type", "text/html; charset=UTF-8")
                .header("Content-Disposition", "inline; filename=incidents-report.html")
                .body(htmlReport);
    }

    @PostMapping("/list")
    public ResponseEntity<Map<String, Object>> getIncidentsList(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String ageing,
            @RequestParam(required = false) String priority,
            @RequestParam(required = false) String assignee,
            @RequestParam(required = false) String search,
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

        // Get sample incidents data
        List<Map<String, Object>> incidents = getSampleIncidentsData();
        
        // Apply filters
        List<Map<String, Object>> filteredIncidents = filterIncidents(incidents, status, ageing, priority, assignee, search);
        
        Map<String, Object> response = new HashMap<>();
        response.put("incidents", filteredIncidents);
        response.put("total", filteredIncidents.size());
        response.put("username", username);
        response.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/details")
    public ResponseEntity<Map<String, Object>> getIncidentDetails(
            @RequestParam String incidentNumber,
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

        // Find incident by number
        List<Map<String, Object>> incidents = getSampleIncidentsData();
        Map<String, Object> incident = incidents.stream()
                .filter(inc -> inc.get("number").equals(incidentNumber))
                .findFirst()
                .orElse(null);

        if (incident == null) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Incident not found");
            return ResponseEntity.status(404).body(response);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("incident", incident);
        response.put("username", username);
        response.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/stats")
    public ResponseEntity<Map<String, Object>> getIncidentStats(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Unauthorized access");
            return ResponseEntity.status(401).body(errorResponse);
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("total", 26);
        stats.put("open", 8);
        stats.put("in_progress", 6);
        stats.put("waiting", 4);
        stats.put("resolved", 5);
        stats.put("closed", 3);

        return ResponseEntity.ok(stats);
    }

    @PostMapping("/charts/priority-month")
    public ResponseEntity<Map<String, Object>> getPriorityCountsCurrentMonth(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Unauthorized access");
            return ResponseEntity.status(401).body(errorResponse);
        }

        // Mock data for current month priority counts
        Map<String, Object> chartData = new HashMap<>();
        chartData.put("labels", Arrays.asList("Priority 1 (Critical)", "Priority 2 (High)", "Priority 3 (Medium)", "Priority 4 (Low)"));
        chartData.put("data", Arrays.asList(12, 18, 25, 8));
        chartData.put("backgroundColor", Arrays.asList("#dc3545", "#fd7e14", "#ffc107", "#28a745"));
        chartData.put("title", "Incident Priority Distribution - Current Month");
        chartData.put("period", "December 2024");

        return ResponseEntity.ok(chartData);
    }

    @PostMapping("/charts/priority-year")
    public ResponseEntity<Map<String, Object>> getPriorityCountsCurrentYear(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Unauthorized access");
            return ResponseEntity.status(401).body(errorResponse);
        }

        // Mock data for current year priority counts
        Map<String, Object> chartData = new HashMap<>();
        chartData.put("labels", Arrays.asList("Priority 1 (Critical)", "Priority 2 (High)", "Priority 3 (Medium)", "Priority 4 (Low)"));
        chartData.put("data", Arrays.asList(145, 220, 310, 95));
        chartData.put("backgroundColor", Arrays.asList("#dc3545", "#fd7e14", "#ffc107", "#28a745"));
        chartData.put("title", "Incident Priority Distribution - Current Year");
        chartData.put("period", "2024");

        return ResponseEntity.ok(chartData);
    }

    @PostMapping("/charts/priority5-trend")
    public ResponseEntity<Map<String, Object>> getPriority5TrendCurrentYear(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Unauthorized access");
            return ResponseEntity.status(401).body(errorResponse);
        }

        // Mock data for Priority 5 tickets trend (monthly for current year)
        Map<String, Object> chartData = new HashMap<>();
        chartData.put("labels", Arrays.asList("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"));
        chartData.put("data", Arrays.asList(8, 12, 15, 10, 18, 22, 16, 14, 20, 25, 19, 13));
        chartData.put("backgroundColor", "#6f42c1");
        chartData.put("borderColor", "#6f42c1");
        chartData.put("title", "Priority 5 Incidents Trend - 2024");
        chartData.put("period", "2024");

        return ResponseEntity.ok(chartData);
    }

    @PostMapping("/email-report")
    public ResponseEntity<String> generateEmailReport(HttpServletRequest request, HttpSession session) {
        String token = (String) session.getAttribute("authToken");
        String username = (String) session.getAttribute("username");
        String clientIpAddress = IpAddressUtil.getClientIpAddress(request);

        if (token == null || !tokenService.isTokenValidForUserAndIp(token, username, clientIpAddress)) {
            return ResponseEntity.status(401).body("Unauthorized access");
        }

        // Generate the HTML email report with assignee distribution
        String htmlReport = generateAssigneeDistributionReport(username);
        
        return ResponseEntity.ok()
                .header("Content-Type", "text/html; charset=UTF-8")
                .header("Content-Disposition", "inline; filename=assignee-distribution-report.html")
                .body(htmlReport);
    }

    private String generateAssigneeDistributionReport(String username) {
        // Get sample incidents data
        List<Map<String, Object>> incidents = getSampleIncidentsData();
        
        // Calculate assignee distribution
        Map<String, Map<String, Integer>> assigneeStats = calculateAssigneeDistribution(incidents);
        
        // Generate HTML report
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>");
        html.append("<html lang=\"en\">");
        html.append("<head>");
        html.append("<meta charset=\"UTF-8\">");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.append("<title>Assignee Distribution Report</title>");
        html.append("<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }");
        html.append(".header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }");
        html.append(".summary { background-color: #e9ecef; padding: 15px; border-radius: 8px; margin-bottom: 20px; }");
        html.append(".table { margin-top: 20px; background-color: white; }");
        html.append(".assignee-name { font-weight: bold; color: #495057; }");
        html.append(".total-count { background-color: #007bff; color: white; font-weight: bold; }");
        html.append(".priority-1 { background-color: #dc3545; color: white; }");
        html.append(".priority-2 { background-color: #fd7e14; color: white; }");
        html.append(".priority-3 { background-color: #ffc107; color: #212529; }");
        html.append(".priority-4 { background-color: #28a745; color: white; }");
        html.append("</style>");
        html.append("</head>");
        html.append("<body>");
        
        // Header
        html.append("<div class=\"header\">");
        html.append("<h1><i class=\"fas fa-envelope\"></i> Assignee Distribution Report</h1>");
        html.append("<p class=\"mb-0\">Generated for: ").append(username).append(" | Date: ").append(LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd"))).append("</p>");
        html.append("</div>");
        
        // Summary
        html.append("<div class=\"summary\">");
        html.append("<h4>Report Summary</h4>");
        html.append("<p><strong>Total Incidents:</strong> ").append(incidents.size()).append("</p>");
        html.append("<p><strong>Unique Assignees:</strong> ").append(assigneeStats.size()).append("</p>");
        html.append("<p><strong>Report Type:</strong> Incident Count Distribution by Assignee</p>");
        html.append("</div>");
        
        // Assignee distribution table
        html.append("<table class=\"table table-striped table-hover\">");
        html.append("<thead class=\"table-dark\">");
        html.append("<tr>");
        html.append("<th>Assignee</th>");
        html.append("<th class=\"text-center\">Total Incidents</th>");
        html.append("<th class=\"text-center\">Priority 1</th>");
        html.append("<th class=\"text-center\">Priority 2</th>");
        html.append("<th class=\"text-center\">Priority 3</th>");
        html.append("<th class=\"text-center\">Priority 4</th>");
        html.append("</tr>");
        html.append("</thead>");
        html.append("<tbody>");
        
        // Sort assignees by total count (descending)
        assigneeStats.entrySet().stream()
            .sorted((e1, e2) -> Integer.compare(e2.getValue().get("total"), e1.getValue().get("total")))
            .forEach(entry -> {
                String assignee = entry.getKey();
                Map<String, Integer> stats = entry.getValue();
                
                html.append("<tr>");
                html.append("<td class=\"assignee-name\">").append(formatAssignee(assignee)).append("</td>");
                html.append("<td class=\"text-center total-count\">").append(stats.get("total")).append("</td>");
                html.append("<td class=\"text-center priority-1\">").append(stats.getOrDefault(1, 0)).append("</td>");
                html.append("<td class=\"text-center priority-2\">").append(stats.getOrDefault(2, 0)).append("</td>");
                html.append("<td class=\"text-center priority-3\">").append(stats.getOrDefault(3, 0)).append("</td>");
                html.append("<td class=\"text-center priority-4\">").append(stats.getOrDefault(4, 0)).append("</td>");
                html.append("</tr>");
            });
        
        html.append("</tbody>");
        html.append("</table>");
        
        // Footer
        html.append("<div class=\"mt-4 text-center text-muted\">");
        html.append("<p><small>This report shows the distribution of incidents by assignee and priority level.</small></p>");
        html.append("</div>");
        
        html.append("</body>");
        html.append("</html>");
        
        return html.toString();
    }

    private Map<String, Map<String, Integer>> calculateAssigneeDistribution(List<Map<String, Object>> incidents) {
        Map<String, Map<String, Integer>> assigneeStats = new HashMap<>();
        
        for (Map<String, Object> incident : incidents) {
            String assignee = (String) incident.get("assignee");
            Integer priority = (Integer) incident.get("priority");
            
            assigneeStats.computeIfAbsent(assignee, k -> new HashMap<>());
            Map<String, Integer> stats = assigneeStats.get(assignee);
            
            // Increment total count
            stats.put("total", stats.getOrDefault("total", 0) + 1);
            
            // Increment priority-specific count
            stats.put(priority.toString(), stats.getOrDefault(priority.toString(), 0) + 1);
            stats.put(String.valueOf(priority), stats.getOrDefault(priority.toString(), 0) + 1);
        }
        
        return assigneeStats;
    }

    private String generateIncidentsReport(String status, String ageing, String priority, String assignee, String search, String username) {
        // Sample incidents data (same as in the frontend)
        List<Map<String, Object>> incidents = getSampleIncidentsData();
        
        // Apply filters
        List<Map<String, Object>> filteredIncidents = filterIncidents(incidents, status, ageing, priority, assignee, search);
        
        // Generate HTML report
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>");
        html.append("<html lang=\"en\">");
        html.append("<head>");
        html.append("<meta charset=\"UTF-8\">");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.append("<title>ServiceNow Incidents Report</title>");
        html.append("<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }");
        html.append(".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 0; margin-bottom: 20px; }");
        html.append(".summary { background-color: #f8f9fa; padding: 15px; border-radius: 0; margin-bottom: 20px; }");
        html.append(".table { margin-top: 20px; }");
        html.append(".badge { font-size: 0.8rem; border-radius: 0; }");
        html.append(".priority-1 { background-color: #dc3545; color: white; }");
        html.append(".priority-2 { background-color: #fd7e14; color: white; }");
        html.append(".priority-3 { background-color: #ffc107; color: #212529; }");
        html.append(".priority-4 { background-color: #28a745; color: white; }");
        html.append(".status-open { background-color: #dc3545; color: white; }");
        html.append(".status-in-progress { background-color: #ffc107; color: #212529; }");
        html.append(".status-waiting { background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%); color: white; }");
        html.append(".status-resolved { background-color: #28a745; color: white; }");
        html.append(".status-closed { background: linear-gradient(135deg, #6c757d 0%, #495057 100%); color: white; }");
        html.append("</style>");
        html.append("</head>");
        html.append("<body>");
        
        // Header
        html.append("<div class=\"header\">");
        html.append("<h1><i class=\"fas fa-exclamation-triangle\"></i> ServiceNow Incidents Report</h1>");
        html.append("<p class=\"mb-0\">Generated for: ").append(username).append(" | Date: ").append(LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd"))).append("</p>");
        html.append("</div>");
        
        // Summary
        html.append("<div class=\"summary\">");
        html.append("<h4>Report Summary</h4>");
        html.append("<p><strong>Total Incidents:</strong> ").append(filteredIncidents.size()).append("</p>");
        if (status != null && !status.equals("all")) {
            html.append("<p><strong>Status Filter:</strong> ").append(status.toUpperCase()).append("</p>");
        }
        if (ageing != null && !ageing.equals("all")) {
            html.append("<p><strong>Ageing Filter:</strong> ").append(ageing).append(" days</p>");
        }
        if (priority != null && !priority.isEmpty()) {
            html.append("<p><strong>Priority Filter:</strong> ").append(priority).append("</p>");
        }
        if (assignee != null && !assignee.isEmpty()) {
            html.append("<p><strong>Assignee Filter:</strong> ").append(assignee).append("</p>");
        }
        if (search != null && !search.isEmpty()) {
            html.append("<p><strong>Search Filter:</strong> ").append(search).append("</p>");
        }
        html.append("</div>");
        
        // Incidents table
        html.append("<table class=\"table table-striped table-hover\">");
        html.append("<thead class=\"table-dark\">");
        html.append("<tr>");
        html.append("<th>Number</th>");
        html.append("<th>Short Description</th>");
        html.append("<th>Priority</th>");
        html.append("<th>State</th>");
        html.append("<th>Assignee</th>");
        html.append("<th>Created</th>");
        html.append("<th>Age (Days)</th>");
        html.append("</tr>");
        html.append("</thead>");
        html.append("<tbody>");
        
        for (Map<String, Object> incident : filteredIncidents) {
            html.append("<tr>");
            html.append("<td><strong>").append(incident.get("number")).append("</strong></td>");
            html.append("<td>").append(incident.get("description")).append("</td>");
            html.append("<td><span class=\"badge priority-").append(incident.get("priority")).append("\">").append(incident.get("priority")).append("</span></td>");
            html.append("<td><span class=\"badge status-").append(incident.get("state").toString().replace("_", "-")).append("\">").append(incident.get("state").toString().replace("_", " ").toUpperCase()).append("</span></td>");
            html.append("<td>").append(formatAssignee(incident.get("assignee").toString())).append("</td>");
            html.append("<td>").append(incident.get("created")).append("</td>");
            html.append("<td><span class=\"badge ").append(getAgeBadgeClass((Integer) incident.get("age"))).append("\">").append(incident.get("age")).append("</span></td>");
            html.append("</tr>");
        }
        
        html.append("</tbody>");
        html.append("</table>");
        
        html.append("</body>");
        html.append("</html>");
        
        return html.toString();
    }

    private List<Map<String, Object>> getSampleIncidentsData() {
        List<Map<String, Object>> incidents = new ArrayList<>();
        
        // Add sample incidents (same data as in the frontend)
        incidents.add(createIncident("INC0012345", "Database connection timeout affecting user login", 1, "open", "john.doe", "2024-01-15", 2));
        incidents.add(createIncident("INC0012346", "Email notifications not being sent", 2, "in_progress", "jane.smith", "2024-01-14", 3));
        incidents.add(createIncident("INC0012347", "Application performance degradation", 1, "waiting", "mike.johnson", "2024-01-13", 4));
        incidents.add(createIncident("INC0012348", "User unable to access reports module", 3, "resolved", "sarah.wilson", "2024-01-12", 5));
        incidents.add(createIncident("INC0012349", "Scheduled job failing intermittently", 2, "open", "john.doe", "2024-01-11", 6));
        incidents.add(createIncident("INC0012350", "Login page loading slowly", 3, "in_progress", "jane.smith", "2024-01-10", 7));
        incidents.add(createIncident("INC0012351", "Data export functionality not working", 4, "closed", "mike.johnson", "2024-01-09", 8));
        incidents.add(createIncident("INC0012352", "Security vulnerability in user management", 1, "open", "sarah.wilson", "2024-01-08", 9));
        incidents.add(createIncident("INC0012353", "Backup process taking too long", 2, "waiting", "john.doe", "2024-01-07", 10));
        incidents.add(createIncident("INC0012354", "Mobile app not syncing data", 3, "resolved", "jane.smith", "2024-01-06", 11));
        incidents.add(createIncident("INC0012355", "API rate limiting too restrictive", 2, "in_progress", "mike.johnson", "2024-01-05", 12));
        incidents.add(createIncident("INC0012356", "User profile images not displaying", 4, "open", "sarah.wilson", "2024-01-04", 13));
        incidents.add(createIncident("INC0012357", "Server memory usage exceeding 90%", 1, "open", "john.doe", "2024-01-03", 14));
        incidents.add(createIncident("INC0012358", "SSL certificate expiring in 30 days", 2, "in_progress", "jane.smith", "2024-01-02", 15));
        incidents.add(createIncident("INC0012359", "User authentication failing for LDAP users", 1, "waiting", "mike.johnson", "2024-01-01", 16));
        incidents.add(createIncident("INC0012360", "Dashboard widgets not loading properly", 3, "resolved", "sarah.wilson", "2023-12-31", 17));
        incidents.add(createIncident("INC0012361", "File upload size limit too restrictive", 4, "closed", "john.doe", "2023-12-30", 18));
        incidents.add(createIncident("INC0012362", "Database backup job failing", 2, "open", "jane.smith", "2023-12-29", 19));
        incidents.add(createIncident("INC0012363", "Email server not responding", 1, "in_progress", "mike.johnson", "2023-12-28", 20));
        incidents.add(createIncident("INC0012364", "User session timeout too short", 3, "waiting", "sarah.wilson", "2023-12-27", 21));
        incidents.add(createIncident("INC0012365", "Report generation taking too long", 2, "resolved", "john.doe", "2023-12-26", 22));
        incidents.add(createIncident("INC0012366", "Mobile app crashing on iOS devices", 1, "open", "jane.smith", "2023-12-25", 23));
        incidents.add(createIncident("INC0012367", "API endpoint returning 500 errors", 2, "in_progress", "mike.johnson", "2023-12-24", 24));
        incidents.add(createIncident("INC0012368", "User permissions not working correctly", 3, "closed", "sarah.wilson", "2023-12-23", 25));
        incidents.add(createIncident("INC0012369", "System logs consuming too much disk space", 4, "open", "john.doe", "2023-12-22", 26));
        incidents.add(createIncident("INC0012370", "Third-party integration API changes", 2, "waiting", "jane.smith", "2023-12-21", 27));
        
        return incidents;
    }

    private Map<String, Object> createIncident(String number, String description, int priority, String state, String assignee, String created, int age) {
        Map<String, Object> incident = new HashMap<>();
        incident.put("number", number);
        incident.put("description", description);
        incident.put("priority", priority);
        incident.put("state", state);
        incident.put("assignee", assignee);
        incident.put("created", created);
        incident.put("age", age);
        return incident;
    }

    private List<Map<String, Object>> filterIncidents(List<Map<String, Object>> incidents, String status, String ageing, String priority, String assignee, String search) {
        return incidents.stream()
                .filter(incident -> {
                    // Status filter
                    if (status != null && !status.equals("all") && !incident.get("state").equals(status)) {
                        return false;
                    }

                    // Ageing filter
                    if (ageing != null && !ageing.equals("all")) {
                        int age = (Integer) incident.get("age");
                        switch (ageing) {
                            case "0-1":
                                if (age > 1) return false;
                                break;
                            case "2-3":
                                if (age < 2 || age > 3) return false;
                                break;
                            case "4-7":
                                if (age < 4 || age > 7) return false;
                                break;
                            case "7+":
                                if (age <= 7) return false;
                                break;
                        }
                    }

                    // Priority filter
                    if (priority != null && !priority.isEmpty() && !incident.get("priority").toString().equals(priority)) {
                        return false;
                    }

                    // Assignee filter
                    if (assignee != null && !assignee.isEmpty() && !incident.get("assignee").equals(assignee)) {
                        return false;
                    }

                    // Search filter
                    if (search != null && !search.isEmpty()) {
                        String searchText = (incident.get("number") + " " + incident.get("description") + " " + incident.get("assignee")).toLowerCase();
                        if (!searchText.contains(search.toLowerCase())) {
                            return false;
                        }
                    }

                    return true;
                })
                .collect(java.util.stream.Collectors.toList());
    }

    private String formatAssignee(String assignee) {
        return assignee.replace(".", " ").replaceAll("\\b\\w", "").toUpperCase();
    }

    private String getAgeBadgeClass(int age) {
        if (age <= 1) return "bg-success";
        if (age <= 3) return "bg-warning";
        if (age <= 7) return "bg-danger";
        return "bg-dark";
    }
}
