package com.example.back_end01.config.jwt;

import com.example.back_end01.Account.Account;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public class JwtProvider {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-expiration}")
    private long accessExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String createAccessToken(Map<String, Object> claims) {
        return createToken(claims, accessExpiration);
    }

    public String createRefreshToken(Map<String, Object> claims) {
        return createToken(claims, refreshExpiration);
    }

    private String createToken(Map<String, Object> claims, long expiration) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Account parseAccount(String token) {
        Claims claims = parseClaims(token);

        return Account.builder()
                .id(claims.get("id", Long.class))
                .email(claims.get("email", String.class)) // 또는 claims.getSubject()
                .name(claims.get("name", String.class))
                .provider(claims.get("provider", String.class))
                .profileImage(claims.get("profileImage", String.class))
                .role(Account.Role.valueOf(claims.get("role", String.class)))
//                .enabled(true) // 토큰에는 없을 수도 있으니 기본값 지정
                .build();
    }


    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException | ExpiredJwtException e) {
            return false;
        }
    }

    public boolean isMy(){
        return true;
    }

    public String getEmail(String token) {
        return parseClaims(token).getSubject();
    }
}

