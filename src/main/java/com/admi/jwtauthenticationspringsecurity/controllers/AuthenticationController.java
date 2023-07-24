package com.admi.jwtauthenticationspringsecurity.controllers;

import com.admi.jwtauthenticationspringsecurity.entities.CustomRole;
import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.exceptions.AppException;
import com.admi.jwtauthenticationspringsecurity.services.AuthenticationService;
import com.admi.jwtauthenticationspringsecurity.services.UserService;
import com.admi.jwtauthenticationspringsecurity.utils.JwtBody;
import com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils.ACCESS_TOKEN_EXPIRATION_TIME;

@RestController
@CrossOrigin
public class AuthenticationController {
    private  final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final AuthenticationService authenticationService;
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    public AuthenticationController(PasswordEncoder passwordEncoder, UserService userService, AuthenticationService authenticationService) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register/user")
    public ResponseEntity<CustomUser> addUser(@RequestBody CustomUser user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        logger.info("registering a user : \n{}",user);
        CustomUser customUser = userService.saveUser(user);
        return ResponseEntity.ok(customUser);
    }

    @PostMapping("/user/login")
    public ResponseEntity<JwtBody> authenticateUser(@RequestBody CustomUser user) throws Exception {
        //search for how to execute the filter that is responsible for the /login end point action
        try {
            Authentication authentication = authenticationService.attemptAuthentication(user);
            logger.info("the authentication is done");
            HttpHeaders headers  = authenticationService.successfulAuthentication(authentication);
            String accessToken = headers.get("access-token").get(0);
            String refreshToken = headers.get("refresh-token").get(0);
            return new ResponseEntity<>(new JwtBody(accessToken,refreshToken),headers, HttpStatus.OK);

        }catch (BadCredentialsException credentialsException){
            return new ResponseEntity<>(new JwtBody("invalid credentials","invalid"), HttpStatus.UNAUTHORIZED);
        }

    }
    @GetMapping("/token/refresh")
    public ResponseEntity<JwtBody> requestAccessToken(HttpServletRequest request, HttpServletResponse response){
        logger.info("requesting to refresh the token");
        String authorizationHeader = request.getHeader("Authorization");
        logger.info("the authorization header : {}",authorizationHeader);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refreshToken = authorizationHeader.substring(7);
                Algorithm algorithm = Algorithm.HMAC256(SecurityUtils.HMAC_KEY);
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT jwt = verifier.verify(refreshToken);
                logger.info("jwt refresh token is valid ");
                String username = jwt.getSubject();
                CustomUser user = userService.loadUserByUsername(username).orElse(null);
                logger.info("generating access token");
                String accessToken = SecurityUtils.generateToken(
                        user.getUsername(),
                        user.getRoles().stream().map(CustomRole::getRoleName).toList(),
                        request.getRequestURI().toString(),
                        ACCESS_TOKEN_EXPIRATION_TIME
                );
                logger.info("token generated");
                logger.info("sending to target");
                return new ResponseEntity<>(new JwtBody(accessToken,refreshToken),HttpStatus.OK);
            } catch (Exception e) {
                throw new AppException(e.getMessage(),HttpStatus.UNAUTHORIZED);
            }

        }else
            throw new AppException("The token format is not correct",HttpStatus.UNAUTHORIZED);

    }

}

