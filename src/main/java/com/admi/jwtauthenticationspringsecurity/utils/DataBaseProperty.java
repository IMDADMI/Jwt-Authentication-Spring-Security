package com.admi.jwtauthenticationspringsecurity.utils;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties("database")
@Configuration
@Data
public class DataBaseProperty {
    private String username;
    private String password;
    private String url;

}
