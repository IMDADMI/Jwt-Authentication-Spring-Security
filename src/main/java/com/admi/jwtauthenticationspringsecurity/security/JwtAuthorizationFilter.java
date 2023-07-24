package com.admi.jwtauthenticationspringsecurity.security;

import com.admi.jwtauthenticationspringsecurity.aop.ErrorDTO;
import com.admi.jwtauthenticationspringsecurity.utils.SecurityUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.info("a request is sent to the server");

        if(!SecurityUtils.verifyPath(request.getServletPath())){
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            logger.info("the Authorization header is : {}",authorizationHeader);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                logger.info("a Bearer container request ");
                try {
                    String accessToken = authorizationHeader.substring(7);
                    Authentication authentication = SecurityUtils.verifyToken(accessToken);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    logger.info("the authentication object is : {}",SecurityContextHolder.getContext().getAuthentication());
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    logger.error("daaaamn that's hard : {}",e.getMessage());
                    SecurityContextHolder.clearContext();
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),ErrorDTO.builder().message(e.getMessage()).build());
//                    throw new AppException(e.getMessage(), HttpStatus.UNAUTHORIZED);
                }
            } else
                filterChain.doFilter(request, response);
        }else
            filterChain.doFilter(request,response);

    }
}
