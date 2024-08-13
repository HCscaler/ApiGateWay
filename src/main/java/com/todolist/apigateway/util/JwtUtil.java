package com.todolist.apigateway.util;

import java.security.Key;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    private Key key;

    @PostConstruct
    public void init() {
        if (jwtSecret == null || jwtSecret.length() < 64) {
            throw new IllegalArgumentException("JWT secret key must be at least 64 characters long for HS512 algorithm.");
        }
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        logger.info("JWT secret key initialized successfully.");
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Long getUserIdFromJWT(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return Long.parseLong(claims.getSubject());
    }

    public String getUsernameFromJWT(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.getSubject();
    }

    public List<String> getRolesFromJWT(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.get("roles", List.class);
    }

    public boolean validateToken(String authToken) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(authToken);
            logger.info("JWT token is valid.");
            return true;
        } catch (Exception ex) {
            logger.error("Invalid JWT token", ex);
        }
        return false;
    }
}


//package com.todolist.apigateway.util;
//
//import java.security.Key;
//import java.util.List;
//import java.util.Date;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.stereotype.Component;
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.security.Keys;
//
//@Component
//public class JwtUtil {
//
//    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
//
//    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
//
//    public Claims getAllClaimsFromToken(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    public Long getUserIdFromJWT(String token) {
//        Claims claims = getAllClaimsFromToken(token);
//        return Long.parseLong(claims.getSubject());
//    }
//
//    public String getUsernameFromJWT(String token) {
//        // Assuming username is stored in the "sub" claim
//        Claims claims = getAllClaimsFromToken(token);
//        return claims.getSubject(); // Adjust if username is stored differently
//    }
//
//    public List<String> getRolesFromJWT(String token) {
//        Claims claims = getAllClaimsFromToken(token);
//        return claims.get("roles", List.class);
//    }
//
//    public boolean validateToken(String authToken) {
//        try {
//            Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(authToken);
//            return true;
//        } catch (Exception ex) {
//            logger.error("Invalid JWT token", ex);
//        }
//        return false;
//    }
//}
////////////////////////////////////////////////////////

//package com.todolist.apigateway.util;
//
//import java.security.Key;
//
//
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.stereotype.Component;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.security.Keys;
//
//@Component
//public class JwtUtil {
//    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
//
//    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
//
//    public Long getUserIdFromJWT(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//
//        return Long.parseLong(claims.getSubject());
//    }
//
//    public String getUsernameFromJWT(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//
//        return claims.getSubject();
//    }
//
//    public boolean validateToken(String authToken) {
//        try {
//            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(authToken);
//            return true;
//        } catch (Exception ex) {
//            logger.error("Invalid JWT token", ex);
//        }
//        return false;
//    }
//}
