@echo off
title ServiceNow Dashboard
echo Starting ServiceNow Dashboard...
echo.

REM Change to the directory containing this batch file
cd /d "%~dp0"

REM Check if Java is installed
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Java is not installed or not in PATH
    echo Please install Java 21 or later
    pause
    exit /b 1
)

REM Check if JAR file exists
if not exist "target\thymeleaf-login-1.0.0.jar" (
    echo ERROR: JAR file not found at target\thymeleaf-login-1.0.0.jar
    echo Please build the project first using: mvn clean package
    pause
    exit /b 1
)

echo Dashboard is starting...
echo Browser will open automatically once the server is ready...
echo.
echo To stop the application, close this window or press Ctrl+C
echo.

REM Run the JAR file (browser will open automatically from Spring Boot)
java -jar target\thymeleaf-login-1.0.0.jar

echo.
echo Dashboard has stopped.
pause
