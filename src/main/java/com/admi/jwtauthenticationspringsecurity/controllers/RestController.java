package com.admi.jwtauthenticationspringsecurity.controllers;
import com.admi.jwtauthenticationspringsecurity.entities.CustomRole;
import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.exceptions.AppException;
import com.admi.jwtauthenticationspringsecurity.services.RoleService;
import com.admi.jwtauthenticationspringsecurity.services.RoleToUser;
import com.admi.jwtauthenticationspringsecurity.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@org.springframework.web.bind.annotation.RestController
public class RestController {
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    private UserService userService;
    private RoleService roleService;


    public RestController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }


    @PostMapping("/role")
    @Secured({"ADMIN"})
    public CustomRole addRole(@RequestBody CustomRole role){
        logger.info("adding new role : {}",role);
        return roleService.saveRole(role);
    }

    @GetMapping("/user")
    @Secured({"ADMIN","USER"})
    public List<CustomUser> listUser(){
        return userService.listUsers();
    }
    @Secured({"ADMIN"})
    @PostMapping("/user/role")
    public void addRoleToUser(@RequestBody RoleToUser roleToUser){
        logger.info("adding a role to a user {} -> {}",roleToUser.getRole(),roleToUser.getUser());
        userService.addRoleToUser(roleToUser.getUser(),roleToUser.getRole());
    }

    @GetMapping("/user/test")
    public String test(){
        return "HELLO IM ADMI";
    }

}
