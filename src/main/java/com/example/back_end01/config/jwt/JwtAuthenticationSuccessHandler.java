package com.example.back_end01.config.jwt;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AuthenticatedAccount;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        Object principal = authentication.getPrincipal();

        if (!(principal instanceof AuthenticatedAccount)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unknown principal type.");
            return;
        }

        Account account = ((AuthenticatedAccount) principal).getAccount();
//        Collection<? extends GrantedAuthority> authorities =
//                ((AuthenticatedAccount) principal).getAuthorities();

        Map<String, Object> claims = account.toClaims();// JWT 발급

        String accessToken = jwtProvider.createAccessToken(claims);
        String refreshToken = jwtProvider.createRefreshToken(claims);

        // JSON 응답
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        Map<String, String> tokens = Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken
        );

        new ObjectMapper().writeValue(response.getWriter(), tokens);
    }
}
