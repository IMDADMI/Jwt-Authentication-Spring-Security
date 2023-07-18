package com.admi.jwtauthenticationspringsecurity.repositories;

import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<CustomUser, Long> {
    CustomUser findCustomUserByUsername(String username);
    CustomUser findCustomUserById(Long id);
}
