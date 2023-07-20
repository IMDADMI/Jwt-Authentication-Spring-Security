package com.admi.jwtauthenticationspringsecurity.services;

import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

public interface AuthenticationService {

    Authentication attemptAuthentication(CustomUser user) throws Exception;
    HttpHeaders successfulAuthentication(Authentication authentication) throws BadCredentialsException;
    Boolean isAuthenticated();
}
