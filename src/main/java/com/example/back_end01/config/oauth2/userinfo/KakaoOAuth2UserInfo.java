package com.example.back_end01.config.oauth2.userinfo;

import java.util.HashMap;
import java.util.Map;

//public class KakaoOAuth2UserInfo extends OAuth2UserInfo {
//
//    private final Map<String, Object> kakaoAccount;
//    private final Map<String, Object> profile;
//
//    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
//        super(attributes);
//        this.kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
//        this.profile = (Map<String, Object>) kakaoAccount.get("profile");
//    }
//
//    @Override
//    public String getProviderId() {
//        return String.valueOf(attributes.get("id"));
//    }
//
//    @Override
//    public String getEmail() {
//        return (String) kakaoAccount.get("email");
//    }
//
//    @Override
//    public String getName() {
//        return (String) profile.get("nickname");
//    }
//
//    @Override
//    public String getImageUrl() {
//        return (String) profile.get("profile_image_url");
//    }
//}


public class KakaoOAuth2UserInfo extends OAuth2UserInfo {

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super(new HashMap<>(attributes));

        // 필요한 정보 추출
        String id = String.valueOf(attributes.get("id"));

        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        String email = (String) kakaoAccount.get("email");
        String nickname = (String) profile.get("nickname");
        String profileImageUrl = (String) profile.get("profile_image_url");

        // 플랫하게 attributes에 직접 넣기
        this.attributes.put("id", id);
        this.attributes.put("email", email);
        this.attributes.put("nickname", nickname);
        this.attributes.put("profile_image_url", profileImageUrl);
    }

    @Override
    public String getProviderId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("nickname");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("profile_image_url");
    }
}
