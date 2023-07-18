package com.admi.jwtauthenticationspringsecurity.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class SecurityUtils {
    public static final String HMAC_KEY = "#YOUR$KEY@HERE!";
    public static final int ACCESS_TOKEN_EXPIRATION_TIME = 5 * 60 * 1000;
    public static final int REFRESH_TOKEN_EXPIRATION_TIME = 30 * 24 * 3600 * 1000;

    public static String generateToken (String username, List<String> authorities, String issuer,int expiredAt){
        JWTCreator.Builder token = JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis()+expiredAt))
                .withIssuer(issuer)
                .withClaim("roles",authorities);
        if(authorities == null)
            return token.sign(Algorithm.HMAC256(HMAC_KEY));
        return token.withClaim("roles",authorities).sign(Algorithm.HMAC256(HMAC_KEY));
    }
}
