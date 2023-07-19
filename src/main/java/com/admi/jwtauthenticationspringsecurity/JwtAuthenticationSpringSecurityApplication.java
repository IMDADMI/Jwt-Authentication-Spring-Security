package com.admi.jwtauthenticationspringsecurity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtAuthenticationSpringSecurityApplication {

    @Value("db.username")
    String ss;

    public static void main(String[] args) {
//        SpringApplication.run(JwtAuthenticationSpringSecurityApplication.class, args);
        JwtAuthenticationSpringSecurityApplication application = new JwtAuthenticationSpringSecurityApplication();
        System.out.println(application.ss);
    }

}
