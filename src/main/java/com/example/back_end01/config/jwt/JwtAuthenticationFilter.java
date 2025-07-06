package com.example.back_end01.config.jwt;

import com.example.back_end01.Account.Account;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;


/**
 * 1. Access Token 검증
 * 2. Refresh Token 검증
 * 3. Access Token 재발급
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

          String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7);

            if (jwtProvider.validateToken(accessToken)) {
                Account account = jwtProvider.parseAccount(accessToken);
                setAuthentication(account, request);
                filterChain.doFilter(request, response);
                return;
            }

            // ❗️accessToken 만료된 경우 → refreshToken 확인
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("refreshToken".equals(cookie.getName())) {
                        String refreshToken = cookie.getValue();

                        if (jwtProvider.validateToken(refreshToken)) {
                            Account account = jwtProvider.parseAccount(refreshToken);
                            setAuthentication(account, request);

                            // ✅ accessToken 재발급
                            Map<String, Object> claims = account.toClaims();
                            String newAccessToken = jwtProvider.createAccessToken(claims);
                            response.setHeader("Authorization", "Bearer " + newAccessToken);
                            filterChain.doFilter(request, response);
                            return;
                        }
                    }
                }
            }

        }
        filterChain.doFilter(request, response);
    }



    private void setAuthentication(Account account, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                account, null, List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole().name()))
        );
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}

