package com.admi.jwtauthenticationspringsecurity.configurations;

import com.admi.jwtauthenticationspringsecurity.aop.CustomAccessDeniedHandler;
import com.admi.jwtauthenticationspringsecurity.aop.UserAuthenticationEntryPoint;
import com.admi.jwtauthenticationspringsecurity.security.CustomeUserDetailsService;
import com.admi.jwtauthenticationspringsecurity.security.JwtAuthorizationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

    private AuthenticationManager authenticationManager;
    private CustomeUserDetailsService userDetailsService;
    private UserAuthenticationEntryPoint userAuthEntryPoint;

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
                        .exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(new CustomAccessDeniedHandler()))
                        //search for how to include this re member me services in your security
//                        .rememberMe(httpSecurityRememberMeConfigurer -> httpSecurityRememberMeConfigurer.rememberMeServices(new RememberMeSer()))
                        //we can create our custom error message when a security problem occurs
                        .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                                httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(userAuthEntryPoint))
                        .csrf(AbstractHttpConfigurer::disable)
                        .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                        .headers(httpSecurityHeadersConfigurer -> httpSecurityHeadersConfigurer.frameOptions().disable())
                        .authorizeHttpRequests(
                                authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                                        .antMatchers("/token/refresh","/login/**","/register/user","/user/login").permitAll()

                                        .anyRequest().authenticated())
                        .authenticationManager(authenticationManager)
//                        .addFilter(new JwtAuthenticationFilter(authenticationManager))
                        //this filter get executed once per request and before other security filer in the filter chain
                        .addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                        .build();

    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public FilterRegistrationBean corsConfigurer() {
        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.addAllowedOrigin("http://localhost:5173");
        corsConfiguration.setAllowedHeaders(Arrays.asList(HttpHeaders.AUTHORIZATION,HttpHeaders.CONTENT_TYPE,HttpHeaders.ACCEPT));
        corsConfiguration.setAllowedMethods(Arrays.asList(
                HttpMethod.GET.name(),
                HttpMethod.PUT.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.POST.name()
        ));
        corsConfiguration.setMaxAge(3600L);
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**",corsConfiguration);
        FilterRegistrationBean bean =  new FilterRegistrationBean(new CorsFilter(urlBasedCorsConfigurationSource));
        //because the request may be rejected by other filters before this cors filter
        bean.setOrder(-102);
        return bean;
    }
}































