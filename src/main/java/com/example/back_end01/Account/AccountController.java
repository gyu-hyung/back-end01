package com.example.back_end01.Account;

import com.example.back_end01.config.firebase.FirebaseTokenVerifier;
import com.example.back_end01.config.jwt.JwtProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/account")
@RequiredArgsConstructor
public class AccountController {

    private final FirebaseTokenVerifier firebaseTokenVerifier;

    private final AccountRepository accountRepository;
    private final JwtProvider jwtProvider;



    // 현재 인증된 사용자 정보 조회 (JWT 기반)
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal Account account) {
        if (account == null) {
            return ResponseEntity.status(401).body("Unauthorized");
        }

        return ResponseEntity.ok(account);
    }

    /**
     * firebase login
     * @param authHeader
     * @return JWT Token(access, refresh)
     * @throws FirebaseAuthException
     */
    @PostMapping("/auth/firebase-login")
    public ResponseEntity<?> loginWithFirebase(@RequestHeader("Authorization") String authHeader) throws FirebaseAuthException {
        String idToken = authHeader.replace("Bearer ", "");

        FirebaseToken firebaseToken = firebaseTokenVerifier.verifyIdToken(idToken);
        String firebaseUid = firebaseToken.getUid();
        String email = firebaseToken.getEmail();

        Account account = accountRepository.findByProviderAndProviderId("firebase", firebaseUid)
                .orElseGet(() -> {
                    Account newAccount = Account.builder()
                            .provider("firebase")
                            .providerId(firebaseUid)
                            .email(email)
                            .name(firebaseToken.getName())
                            .role(Account.Role.USER)
                            .enabled(true)
                            .build();
                    return accountRepository.save(newAccount);
                });

        Map<String, Object> claims = account.toClaims();
        // 2. 자체 JWT 발급
        String accessToken = jwtProvider.createAccessToken(claims);
        String refreshToken = jwtProvider.createRefreshToken(claims);
        Map<String, String> tokens = Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken
        );

        return ResponseEntity.ok(tokens);
    }

}