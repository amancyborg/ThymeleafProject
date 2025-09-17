package com.example.thymeleaflogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@SpringBootApplication
@EnableScheduling
public class ThymeleafLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThymeleafLoginApplication.class, args);
    }

    @Component
    public static class BrowserLauncher {
        
        @EventListener(ApplicationReadyEvent.class)
        public void openBrowser() {
            String url = "http://localhost:8080";
            String os = System.getProperty("os.name").toLowerCase();
            
            try {
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    // Use Desktop API (works on Windows, Mac, Linux)
                    Desktop.getDesktop().browse(new URI(url));
                    // Browser opened automatically
                } else if (os.contains("win")) {
                    // Windows fallback
                    Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + url);
                    // Browser opened (Windows)
                } else if (os.contains("mac")) {
                    // Mac fallback
                    Runtime.getRuntime().exec("open " + url);
                    // Browser opened (Mac)
                } else if (os.contains("nix") || os.contains("nux")) {
                    // Linux fallback
                    Runtime.getRuntime().exec("xdg-open " + url);
                    // Browser opened (Linux)
                } else {
                    // Unable to open browser automatically
                }
            } catch (IOException | URISyntaxException e) {
                // Failed to open browser automatically
            }
        }
    }
}
