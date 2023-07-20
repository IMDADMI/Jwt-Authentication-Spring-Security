package com.admi.jwtauthenticationspringsecurity.services;

import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import static com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils.ACCESS_TOKEN_EXPIRATION_TIME;
import static com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils.REFRESH_TOKEN_EXPIRATION_TIME;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    private AuthenticationManagerBuilder managerBuilder;


    public AuthenticationServiceImpl(AuthenticationManagerBuilder managerBuilder) {
        this.managerBuilder = managerBuilder;
    }

    @Override
    public Authentication attemptAuthentication(CustomUser user) throws Exception {
        String username = user.getUsername();
        String password = user.getPassword();
        logger.info("A user is attempting to authenticate");
        logger.info("User info are : username : {},password : {}",username,"* * * * * * * * *");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,password);
        logger.info("authentication the user ...");
        try{
            return managerBuilder.getObject().authenticate(authenticationToken);
        }catch (BadCredentialsException e){
            logger.error("{} : {}",e.getMessage(),e.getCause());
            throw e;
        }

    }

    @Override
    public HttpHeaders successfulAuthentication(Authentication authentication) throws BadCredentialsException {
        if(authentication==null)
            throw new BadCredentialsException("invalid credentials");
        SecurityContext sc = SecurityContextHolder.getContext();
        sc.setAuthentication(authentication);
        logger.info("the authentication passed successfully");
        User user = (User) authentication.getPrincipal();
        logger.info("generating jwt access and refresh tokens");
        String accessToken = SecurityUtils.generateToken(
                user.getUsername(),
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
                "localhost generated token",
                ACCESS_TOKEN_EXPIRATION_TIME
        );
        String refreshToken = SecurityUtils.generateToken(
                user.getUsername(),
                null,
                "localhost generated token",
                REFRESH_TOKEN_EXPIRATION_TIME
        );
       HttpHeaders headers = new HttpHeaders();
        headers.add("access-token",accessToken);
        headers.add("refresh-token",refreshToken);
       return headers;
    }

    @Override
    public Boolean isAuthenticated() {
        return SecurityContextHolder.getContext().getAuthentication().isAuthenticated();
    }
}
