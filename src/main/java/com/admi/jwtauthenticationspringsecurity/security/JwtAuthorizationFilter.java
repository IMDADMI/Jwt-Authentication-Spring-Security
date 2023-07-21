package com.admi.jwtauthenticationspringsecurity.security;

import com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.info("a request is sent to the server");

        if(!SecurityUtils.verifyPath(request.getServletPath())){
            String authorizationHeader = request.getHeader("Authorization");
            logger.info("the Authorization header is : {}",authorizationHeader);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                logger.info("a Bearer container request ");
                try {
                    String accessToken = authorizationHeader.substring(7);
                    Algorithm algorithm = Algorithm.HMAC256(SecurityUtils.HMAC_KEY);
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT jwt = verifier.verify(accessToken);
                    String username = jwt.getSubject();
                    String roles[] = jwt.getClaim("roles").asArray(String.class);
                    logger.info("the roles of this principle are : {}",roles);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    Arrays.stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    logger.error("the token is expired \n{}",e.getCause());
                    response.setHeader("error", e.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    Map<String,String> error = new HashMap<>();
                    error.put("msg",e.getMessage());
                    error.put("status",String.valueOf(HttpServletResponse.SC_UNAUTHORIZED));
                    new ObjectMapper().writeValue(response.getOutputStream(),error);
                }
            } else
                filterChain.doFilter(request, response);
        }else
            filterChain.doFilter(request,response);

    }
}
