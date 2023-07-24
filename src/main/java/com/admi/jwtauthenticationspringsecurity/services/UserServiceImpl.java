package com.admi.jwtauthenticationspringsecurity.services;

import com.admi.jwtauthenticationspringsecurity.entities.CustomRole;
import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.exceptions.AppException;
import com.admi.jwtauthenticationspringsecurity.repositories.RoleRepository;
import com.admi.jwtauthenticationspringsecurity.repositories.UserRepository;
import org.springframework.http.HttpStatus;
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
        return userRepository.findCustomUserByUsername(username);
    }

    @Override
    public CustomUser saveUser(CustomUser customUser) {
        Optional<CustomUser> user = userRepository.findCustomUserByUsername(customUser.getUsername());
        if(user.isPresent())
            throw new AppException("user already exist", HttpStatus.BAD_REQUEST);
        return userRepository.save(user.get());
    }

    @Override
    public void addRoleToUser(String user, String role) {
        Optional<CustomUser> c_user = userRepository.findCustomUserByUsername(user);
        CustomRole c_role = roleRepository.findCustomRoleByRoleName(role);
        c_user.get().getRoles().add(c_role);
        userRepository.save(c_user.get());
    }

    @Override
    public Optional<CustomUser> loadUserById(Long id) {
        return Optional.of(userRepository.findCustomUserById(id));
    }
}
