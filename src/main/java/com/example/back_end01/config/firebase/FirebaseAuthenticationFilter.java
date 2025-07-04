package com.example.back_end01.config.firebase;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AccountRepository;
import com.google.common.net.HttpHeaders;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class FirebaseAuthenticationFilter extends OncePerRequestFilter {

    private final AccountRepository accountRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String idToken = header.substring(7);
        FirebaseToken decodedToken;
        try {
            decodedToken = FirebaseAuth.getInstance().verifyIdToken(idToken);
        } catch (FirebaseAuthException e) {
            filterChain.doFilter(request, response);
            return;
        }

        String uid = decodedToken.getUid();

        //TODO 가지고 있는 사용자 정보로 가입 처리
//                Account account = accountRepository.findByProviderAndProviderId(registrationId, providerId)
//                .orElseGet(() -> {
//                    Account newAccount = Account.builder()
//                            .provider(registrationId)
//                            .providerId(providerId)
//                            .enabled(true)
//                            .email(email)
//                            .name(userInfo.getName())
//                            .profileImage(userInfo.getImageUrl())
//                            .role(Account.Role.USER)
//                            .build();
//                    return accountRepository.save(newAccount);
//                });

        Account account = accountRepository.findByProviderAndProviderId("firebase", uid)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));


        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(account, null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole().name())));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}

