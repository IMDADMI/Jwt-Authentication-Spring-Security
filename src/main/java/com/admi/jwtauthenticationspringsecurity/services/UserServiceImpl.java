package com.admi.jwtauthenticationspringsecurity.services;

import com.admi.jwtauthenticationspringsecurity.entities.CustomRole;
import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.repositories.RoleRepository;
import com.admi.jwtauthenticationspringsecurity.repositories.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    private UserRepository userRepository;
    private RoleRepository roleRepository;

    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public List<CustomUser> listUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<CustomUser> loadUserByUsername(String username) {
        return Optional.of(userRepository.findCustomUserByUsername(username));
    }

    @Override
    public CustomUser saveUser(CustomUser customUser) {
        return userRepository.save(customUser);
    }

    @Override
    public void addRoleToUser(String user, String role) {
        CustomUser c_user = userRepository.findCustomUserByUsername(user);
        CustomRole c_role = roleRepository.findCustomRoleByRoleName(role);
        c_user.getRoles().add(c_role);
    }

    @Override
    public Optional<CustomUser> loadUserById(Long id) {
        return Optional.of(userRepository.findCustomUserById(id));
    }
}
