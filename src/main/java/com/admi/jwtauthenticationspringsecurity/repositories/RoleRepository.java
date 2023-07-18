package com.admi.jwtauthenticationspringsecurity.repositories;

import com.admi.jwtauthenticationspringsecurity.entities.CustomRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<CustomRole,Long> {
    CustomRole findCustomRoleByRoleName(String roleName);
}
