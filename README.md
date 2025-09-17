# Thymeleaf Login Application

A Spring Boot web application with authentication using Thymeleaf for the frontend. This application implements a secure login system with token-based authentication and session management.

## Tech Stack

- **Java 21**
- **Spring Boot 3.2.0**
- **Maven**
- **Thymeleaf** (Frontend templating)
- **Spring Security** (Authentication & Authorization)
- **Bootstrap 5** (UI Framework)

## Features

- ✅ Secure login page with username/password authentication
- ✅ Base64 encoding of credentials for external API calls
- ✅ Token-based authentication with session management
- ✅ Automatic token expiration handling
- ✅ Protected API endpoints
- ✅ Responsive UI with Bootstrap
- ✅ Token cleanup scheduler
- ✅ Session-based authentication with Thymeleaf

## Authentication Flow

1. User enters username and password on the login page
2. Credentials are base64 encoded and sent to external API
3. On successful API response, a token is generated and stored
4. Token is used for all subsequent API calls
5. If token expires, user is redirected to login page
6. Session management ensures secure authentication state

## Project Structure

```
src/
├── main/
│   ├── java/com/example/thymeleaflogin/
│   │   ├── config/          # Configuration classes
│   │   ├── controller/      # REST and MVC controllers
│   │   ├── interceptor/     # Request interceptors
│   │   ├── model/          # Data models
│   │   ├── scheduler/      # Scheduled tasks
│   │   ├── security/       # Security components
│   │   ├── service/        # Business logic services
│   │   └── ThymeleafLoginApplication.java
│   └── resources/
│       ├── templates/      # Thymeleaf templates
│       └── application.yml # Application configuration
└── test/                   # Test files
```

## Getting Started

### Prerequisites

- Java 21 or higher
- Maven 3.6 or higher

### Running the Application

1. Clone the repository
2. Navigate to the project directory
3. Run the application:

```bash
mvn spring-boot:run
```

4. Open your browser and navigate to: `http://localhost:8080`

### Default Configuration

The application is configured to use:
- Port: 8080
- External API: JSONPlaceholder (https://jsonplaceholder.typicode.com)
- Session timeout: 30 minutes
- Token expiration: 30 minutes

## API Endpoints

### Public Endpoints
- `GET /login` - Login page
- `GET /api/public` - Public API endpoint (no authentication required)

### Protected Endpoints
- `GET /dashboard` - User dashboard (requires authentication)
- `GET /api/protected` - Protected API endpoint
- `GET /api/user-info` - Get current user information
- `POST /logout` - Logout endpoint

## Configuration

### External API Configuration

Update `src/main/resources/application.yml` to configure the external API:

```yaml
external:
  api:
    base-url: https://your-api-endpoint.com
    timeout: 5000
```

### Session Configuration

Session settings can be modified in `application.yml`:

```yaml
server:
  servlet:
    session:
      timeout: 30m
      cookie:
        max-age: 1800
        http-only: true
        secure: false
```

## Security Features

- **Token-based Authentication**: Secure token generation and validation
- **Session Management**: HTTP session-based authentication state
- **Automatic Token Cleanup**: Scheduled cleanup of expired tokens
- **Request Interception**: Automatic token validation for protected endpoints
- **CSRF Protection**: Disabled for API endpoints (can be enabled if needed)
- **Secure Headers**: HTTP-only cookies and secure session management

## Testing the Application

1. **Login**: Use any username/password combination
2. **Dashboard**: After successful login, you'll be redirected to the dashboard
3. **API Testing**: Use the buttons on the dashboard to test different API endpoints
4. **Token Expiration**: Wait for token expiration or manually invalidate session to test redirect

## Customization

### Adding New Protected Endpoints

1. Create a new controller method
2. The token validation interceptor will automatically protect it
3. Access user information via `HttpSession`

### Modifying Authentication Logic

1. Update `AuthenticationService.authenticate()` method
2. Modify the external API call logic
3. Adjust token generation and validation as needed

### UI Customization

1. Modify Thymeleaf templates in `src/main/resources/templates/`
2. Update CSS styles in the template files
3. Add new Bootstrap components as needed

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in `application.yml`
2. **External API timeout**: Increase timeout value in configuration
3. **Token expiration**: Check session timeout settings
4. **Login redirect loop**: Verify security configuration

### Logs

Enable debug logging by adding to `application.yml`:

```yaml
logging:
  level:
    com.example: DEBUG
    org.springframework.security: DEBUG
```

## License

This project is for educational and demonstration purposes.



