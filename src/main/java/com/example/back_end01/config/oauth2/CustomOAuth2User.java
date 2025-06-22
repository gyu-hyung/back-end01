package com.example.back_end01.config.oauth2;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AuthenticatedAccount;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class CustomOAuth2User implements OAuth2User, AuthenticatedAccount {


    private final Account account;
    private final Map<String, Object> attributes;

    public CustomOAuth2User(Account account, Map<String, Object> attributes) {
        this.account = account;
        this.attributes = attributes;
    }

    @Override
    public Account getAccount() {
        return this.account;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole().name()));
    }

    @Override
    public String getName() {
        return String.valueOf(account.getId());
    }

}
