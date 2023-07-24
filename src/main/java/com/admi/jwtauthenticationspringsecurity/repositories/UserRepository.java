package com.admi.jwtauthenticationspringsecurity.repositories;

import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<CustomUser, Long> {
    Optional<CustomUser> findCustomUserByUsername(String username);
    CustomUser findCustomUserById(Long id);
}
