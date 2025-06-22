package com.example.back_end01.config.formlogin;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final AccountRepository accountRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 이메일로 조회
        Account account = accountRepository.findByProviderAndEmail("formLogin", username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

//        Account account = createTempUser(username);

        return new CustomUserDetails(account);
    }

    /**
     * Test 계정
     * @param username
     * @return
     */
    private Account createTempUser(String username) {
        Account account = accountRepository.findByEmail(username)
                .orElseGet(() -> {
                    Account newAccount = Account.builder()
                            .email("user")
                            .password("$2a$10$DMX7Kw/2EkWx8F9kYylm2.8Z0YmnvLTvmT3GekV.uHqUbwUestTRy")//1234
                            .enabled(true)
                            .role(Account.Role.USER)
                            .build();
                    return accountRepository.save(newAccount);
                });
        return account;
    }


//    insert into account(email, enabled, name, password, profile_image, provider, provider_id, ROLE)
//    values (
//'gud5603@naver.com',
//FALSE,
//'조규형',
//        '$2a$10$DMX7Kw/2EkWx8F9kYylm2.8Z0YmnvLTvmT3GekV.uHqUbwUestTRy',
//        'https://ssl.pstatic.net/static/pwe/address/img_profile.png',
//        'formLogin',
//        null,
//        'USER'
//    )


}