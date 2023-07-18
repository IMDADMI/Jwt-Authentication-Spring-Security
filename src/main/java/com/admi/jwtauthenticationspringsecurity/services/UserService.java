package com.admi.jwtauthenticationspringsecurity.services;

import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;

import java.util.List;
import java.util.Optional;

public interface UserService {
    List<CustomUser> listUsers();
    Optional<CustomUser> loadUserByUsername(String username);
    CustomUser saveUser(CustomUser customUser);
    void addRoleToUser(String user, String role);
    Optional<CustomUser> loadUserById(Long id);
}
