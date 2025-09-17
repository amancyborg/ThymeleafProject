package com.example.thymeleaflogin.config;

import com.example.thymeleaflogin.interceptor.TokenValidationInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private TokenValidationInterceptor tokenValidationInterceptor;

    @Override
    public void addInterceptors(@NonNull InterceptorRegistry registry) {
        registry.addInterceptor(tokenValidationInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/login", "/css/**", "/js/**", "/images/**", "/logout", "/api/public", "/external-templates/**");
    }

    @Override
    public void addResourceHandlers(@NonNull ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/external-templates/**")
                .addResourceLocations("file:external-templates/");
    }
}
