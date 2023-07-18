package com.admi.jwtauthenticationspringsecurity.controllers;
import com.admi.jwtauthenticationspringsecurity.entities.CustomRole;
import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.services.RoleService;
import com.admi.jwtauthenticationspringsecurity.services.RoleToUser;
import com.admi.jwtauthenticationspringsecurity.services.UserService;
import com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils.ACCESS_TOKEN_EXPIRATION_TIME;


@org.springframework.web.bind.annotation.RestController
@CrossOrigin
public class RestController {

    private UserService userService;
    private RoleService roleService;
    private PasswordEncoder passwordEncoder;

    public RestController(UserService userService, RoleService roleService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/user")
    public CustomUser addUser(@RequestBody CustomUser user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userService.saveUser(user);
    }
    @PostMapping("/role")
    public CustomRole addRole(@RequestBody CustomRole role){
        return roleService.saveRole(role);
    }
    @PostMapping("/user/role")
    public void addRoleToUser(@RequestBody RoleToUser roleToUser){
        userService.addRoleToUser(roleToUser.getUser(),roleToUser.getRole());
    }
    @GetMapping("/user")
    public List<CustomUser> listUsers (){
        return userService.listUsers();
    }
    @GetMapping("/user/{id}")
    public CustomUser getUserById(@PathVariable String id){
        return userService.loadUserById(Long.parseLong(id)).orElse(null);
    }
    @GetMapping("/token/refresh")
    public void requestAccessToken(HttpServletRequest request,HttpServletResponse response){
        String authorizationHeader = request.getHeader("Authorization");
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


//                String newAccessToken = JWT.create()
//                        .withSubject(user.getUsername())
//                        .withExpiresAt(new Date(System.currentTimeMillis()+ACCESS_TOKEN_EXPIRATION_TIME))
//                        .withIssuer(request.getRequestURI().toString())
//                        .withClaim("roles",user.getRoles().stream().map(CustomRole::getRoleName).toList())
//                        .sign(algorithm);
                Map<String,String> token = new HashMap<>();
                token.put("access-token",accessToken);
                token.put("refresh-token",refreshToken);
                new ObjectMapper().writeValue(response.getOutputStream(),token);
            } catch (Exception e) {

            }
        }
    }


}
