package com.admi.jwtauthenticationspringsecurity.configurations;

import com.admi.jwtauthenticationspringsecurity.security.JwtAuthenticationFilter;
import com.admi.jwtauthenticationspringsecurity.security.JwtAuthorizationFilter;
import com.admi.jwtauthenticationspringsecurity.security.CustomeUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

    private AuthenticationManager authenticationManager;
    private CustomeUserDetailsService userDetailsService;

    public SecurityConfiguration( CustomeUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity httpSecurity) throws Exception{
        AuthenticationManagerBuilder builder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        authenticationManager = builder.build();
        return
                httpSecurity
                        .cors(AbstractHttpConfigurer::disable)
                        .csrf(AbstractHttpConfigurer::disable)
                        .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                        .headers(httpSecurityHeadersConfigurer -> httpSecurityHeadersConfigurer.frameOptions().disable())
                        .authorizeHttpRequests(
                                authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                                        .antMatchers(HttpMethod.POST,"/register/user").permitAll()
                                        .antMatchers("/token/**","/login/**").permitAll()
                                        .anyRequest().authenticated())
                        .authenticationManager(authenticationManager)
                        .addFilter(new JwtAuthenticationFilter(authenticationManager))
                        .addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                        .build();

    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
