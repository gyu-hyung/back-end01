package com.example.back_end01.config.oauth2;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AccountRepository;
import com.example.back_end01.config.oauth2.userinfo.OAuth2UserInfo;
import com.example.back_end01.config.oauth2.userinfo.OAuth2UserInfoFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;


@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final AccountRepository accountRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

//        String json = null;
//        try {
//            json = new ObjectMapper()
//                    .writerWithDefaultPrettyPrinter()
//                    .writeValueAsString(oAuth2User.getAttributes());
//        } catch (JsonProcessingException e) {
//            throw new RuntimeException(e);
//        }
//        System.out.println("[사용자 정보]" + json);


        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // google, naver, kakao.
        Map<String, Object> attributes = oAuth2User.getAttributes();

        //provider별 사용자 포맷 상이. 추상화
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes);
        String providerId = userInfo.getProviderId();
        String email = userInfo.getEmail();

        //프로젝트 도메인 Account
        Account account = accountRepository.findByProviderAndProviderId(registrationId, providerId)
                .orElseGet(() -> {
                    Account newAccount = Account.builder()
                            .provider(registrationId)
                            .providerId(providerId)
                            .enabled(true)
                            .email(email)
                            .name(userInfo.getName())
                            .profileImage(userInfo.getImageUrl())
                            .role(Account.Role.USER)
                            .build();
                    return accountRepository.save(newAccount);
                });

        /**
         * 생성된 CustomOAuth2User는 로그인 시에만 사용합니다.
         * 이 후 요청에서는 사용 X
         */
        return new CustomOAuth2User(account, attributes);
    }
}


