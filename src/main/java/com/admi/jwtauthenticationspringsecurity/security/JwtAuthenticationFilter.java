package com.admi.jwtauthenticationspringsecurity.security;

import com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils.ACCESS_TOKEN_EXPIRATION_TIME;
import static com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils.REFRESH_TOKEN_EXPIRATION_TIME;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getHeader("username");
        if(username == null)
            username = "";
        String password = request.getHeader("password");
        if(password == null)
            password = "";
        logger.info("A user is attempting to authenticate");
        logger.info("User info are : username : {},password : {}",username,"*****************");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,password);
        logger.info("authentication the user ...");
        return authenticationManager.authenticate(authenticationToken);
    }

    @CrossOrigin
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        logger.info("the authentication passed successfully");
        User user = (User) authResult.getPrincipal();
        logger.info("generating jwt access and refresh tokens");
        String accessToken = SecurityUtils.generateToken(
                user.getUsername(),
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
                request.getRequestURI().toString(),
                ACCESS_TOKEN_EXPIRATION_TIME
                );
        String refreshToken = SecurityUtils.generateToken(
                user.getUsername(),
               null,
                request.getRequestURI().toString(),
                REFRESH_TOKEN_EXPIRATION_TIME
        );

        Map<String,String> tokens = new HashMap<>();
        tokens.put("access-token",accessToken);
        tokens.put("refresh-token",refreshToken);
        logger.info("sending the tokens to the response header");
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),tokens);

    }
}
