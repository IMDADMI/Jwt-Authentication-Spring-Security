package com.admi.jwtauthenticationspringsecurity.services;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RoleToUser {
    private String role;
    private String user;
}
