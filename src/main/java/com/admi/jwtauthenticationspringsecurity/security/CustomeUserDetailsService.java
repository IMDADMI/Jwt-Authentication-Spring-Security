package com.admi.jwtauthenticationspringsecurity.security;

import com.admi.jwtauthenticationspringsecurity.entities.CustomUser;
import com.admi.jwtauthenticationspringsecurity.services.UserServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class CustomeUserDetailsService implements UserDetailsService {
    private UserServiceImpl service;
    private Logger logger = LoggerFactory.getLogger(CustomeUserDetailsService.class);
    public CustomeUserDetailsService(UserServiceImpl service) {
        this.service = service;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        CustomUser user = service.loadUserByUsername(username).orElse(null);
        if(user == null){
            logger.error("the user cannot be found");
            throw new UsernameNotFoundException("the user is null");
        }
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(r->authorities.add(new SimpleGrantedAuthority(r.getRoleName())));
        return new User(user.getUsername(),user.getPassword(),authorities);

    }
}
