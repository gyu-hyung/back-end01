package com.example.back_end01.Account;

import com.example.back_end01.config.jwt.JwtProvider;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/account")
@RequiredArgsConstructor
public class AccountController {

    private final AccountRepository accountRepository;
    private final JwtProvider jwtProvider;



    // 현재 인증된 사용자 정보 조회 (JWT 기반)
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal Account account) {
        if (account == null) {
            return ResponseEntity.status(401).body(HttpStatus.UNAUTHORIZED);
        }

        return ResponseEntity.ok(account);
    }

    /**
     * firebase login
     * @param authHeader
     * @return JWT Token(access, refresh)
     * @throws FirebaseAuthException
     */
    @PostMapping("/firebase-login")
    public ResponseEntity<?> loginWithFirebase(@RequestHeader("Authorization") String authHeader) throws FirebaseAuthException {
        String idToken = authHeader.replace("Bearer ", "");

        FirebaseToken decodedToken;
        try {
            decodedToken = FirebaseAuth.getInstance().verifyIdToken(idToken);
        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(401).body(HttpStatus.UNAUTHORIZED);
        }


        String firebaseUid = decodedToken.getUid();
        String email = decodedToken.getEmail();

        Account account = accountRepository.findByProviderAndProviderId("firebase", firebaseUid)
                .orElseGet(() -> {
                    //존재하지 않을 시 생성.
                    Account newAccount = Account.builder()
                            .provider("firebase")
                            .providerId(firebaseUid)
                            .email(email)
                            .name(decodedToken.getName())
                            .role(Account.Role.USER)
                            .enabled(true)
                            .build();
                    return accountRepository.save(newAccount);
                });

        Map<String, Object> claims = account.toClaims();

        // 2. 자체 JWT 발급
        String accessToken = jwtProvider.createAccessToken(claims);
        String refreshToken = jwtProvider.createRefreshToken(claims);

        // RefreshToken을 HttpOnly 쿠키로 설정
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(7 * 24 * 60 * 60);

        Map<String, String> tokens = Map.of(
                "accessToken", accessToken
        );

        return ResponseEntity.ok(tokens);
    }

}