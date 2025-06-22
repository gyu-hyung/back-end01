package com.example.back_end01.config.firebase;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AccountRepository;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class FirebaseJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final AccountRepository accountRepository;

    public FirebaseJwtAuthenticationConverter(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String uid = jwt.getSubject();
        String email = jwt.getClaimAsString("email");
        String name = jwt.getClaimAsString("name");
        String picture = jwt.getClaimAsString("picture");

        //이메일 인증되지 않은 사용자 차단하고 싶다면 email_verified claim 사용 가능
//        Boolean verified = jwt.getClaimAsBoolean("email_verified");
//        if (Boolean.FALSE.equals(verified)) {
//            throw new IllegalStateException("이메일 인증되지 않은 사용자");
//        }

        // DB 조회 및 자동 등록
        Account account = accountRepository.findByProviderId(uid)
                .orElseGet(() -> {
                    Account newAccount = Account.builder()
                            .provider("firebase")
                            .providerId(uid)
                            .email(email)
                            .name(name)
                            .profileImage(picture)
                            .role(Account.Role.USER)
                            .enabled(true)
                            .build();
                    return accountRepository.save(newAccount);
                });

        List<GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole().name()));

        return new UsernamePasswordAuthenticationToken(account, jwt, authorities);
    }

}

