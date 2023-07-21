package com.admi.jwtauthenticationspringsecurity.controllers;
import com.admi.jwtauthenticationspringsecurity.entities.CustomRole;
import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.services.AuthenticationService;
import com.admi.jwtauthenticationspringsecurity.services.RoleService;
import com.admi.jwtauthenticationspringsecurity.services.RoleToUser;
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
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils.ACCESS_TOKEN_EXPIRATION_TIME;


@org.springframework.web.bind.annotation.RestController
//@CrossOrigin (origins = "*" , exposedHeaders = "**")
public class RestController {
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    private UserService userService;
    private RoleService roleService;
    private PasswordEncoder passwordEncoder;
    private AuthenticationService authenticationService;

    public RestController(UserService userService, RoleService roleService, PasswordEncoder passwordEncoder, AuthenticationService authenticationService) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register/user")
    public CustomUser addUser(@RequestBody CustomUser user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        logger.info("registering a user : \n{}",user);
        return userService.saveUser(user);
    }
    @PostMapping("/role")
    @Secured({"ADMIN"})
    public CustomRole addRole(@RequestBody CustomRole role){
        logger.info("adding new role : {}",role);
        return roleService.saveRole(role);
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
    @GetMapping("/user/list")
    public List<CustomUser> listUser(){
        return userService.listUsers();
    }
    @Secured({"ADMIN"})
    @PostMapping("/user/role")
    public void addRoleToUser(@RequestBody RoleToUser roleToUser){
        logger.info("adding a role to a user {} -> {}",roleToUser.getRole(),roleToUser.getUser());
        userService.addRoleToUser(roleToUser.getUser(),roleToUser.getRole());
    }
    @Secured({"ADMIN","USER"})
    @GetMapping("/user/{id}")
    public CustomUser getUserById(@PathVariable String id){
        logger.info("getting the user with the id = {}",id);
        return userService.loadUserById(Long.parseLong(id)).orElse(null);
    }
    @GetMapping("/token/refresh")
    public ResponseEntity<String> requestAccessToken(HttpServletRequest request){
        logger.info("requesting to refresh the token");
        String authorizationHeader = request.getHeader("Authorization");
        logger.info("the authorization header : {}",authorizationHeader);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refreshToken = authorizationHeader.substring(7);
                Algorithm algorithm = Algorithm.HMAC256(SecurityUtils.HMAC_KEY);
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT jwt = verifier.verify(refreshToken);
                String username = jwt.getSubject();
                CustomUser user = userService.loadUserByUsername(username).orElse(null);

                String accessToken = SecurityUtils.generateToken(
                        user.getUsername(),
                        user.getRoles().stream().map(CustomRole::getRoleName).toList(),
                        request.getRequestURI().toString(),
                        ACCESS_TOKEN_EXPIRATION_TIME
                );
                Map<String,String> token = new HashMap<>();
                token.put("access-token",accessToken);
                token.put("refresh-token",refreshToken);
                String tokens = new ObjectMapper().writeValueAsString(token);
                return new ResponseEntity<>(tokens,HttpStatus.OK);
            } catch (Exception e) {
                return new ResponseEntity<>("bad request",HttpStatus.UNAUTHORIZED);
            }

        }else
            return new ResponseEntity<>("the token is expired or the token format is not correct",HttpStatus.UNAUTHORIZED);

    }


}
