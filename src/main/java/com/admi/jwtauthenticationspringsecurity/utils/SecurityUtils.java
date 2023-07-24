package com.admi.jwtauthenticationspringsecurity.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

public class SecurityUtils {
    public static final String HMAC_KEY = "#YOUR$KEY@HERE!";
    public static final long ACCESS_TOKEN_EXPIRATION_TIME = 5 * 60 * 1000;
    public static final long REFRESH_TOKEN_EXPIRATION_TIME = 10 * 24 * 3600 * 1000;
    public static final long REMEMBER_ME_REFRESH_TOKEN_EXPIRATION_TIME = 20 * 24 * 3600 * 1000;
    private static List<String> ignoredPaths = List.of("/token/refresh","/user/test");

    public static String generateToken (String username, List<String> authorities, String issuer,long expiredAt){
        JWTCreator.Builder token = JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis()+expiredAt))
                .withIssuer(issuer)
                .withClaim("roles",authorities);
        if(authorities == null)
            return token.sign(Algorithm.HMAC256(HMAC_KEY));
        return token.withClaim("roles",authorities).sign(Algorithm.HMAC256(HMAC_KEY));
    }

    public static Authentication verifyToken(String token){
        Algorithm algorithm = Algorithm.HMAC256(SecurityUtils.HMAC_KEY);
        JWTVerifier verifier = JWT.require(algorithm).build();
        //here if the validity date has expired then it will throw an exception
        DecodedJWT jwt = verifier.verify(token);

        String username = jwt.getSubject();
        String roles[] = jwt.getClaim("roles").asArray(String.class);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        Arrays.stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        return authenticationToken;
    }

    public static boolean verifyPath(String path) {
        System.out.println("path : "+path);
        for(String p : ignoredPaths)
            if(p.equals(path))
                return true;
        return false;
    }
}
