package com.example.back_end01.config.formlogin;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AuthenticatedAccount;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails, AuthenticatedAccount {

    private final Account account;

    public CustomUserDetails(Account account) {
        this.account = account;
    }

    @Override
    public Account getAccount() {
        return this.account;
    }

    @Override
    public String getUsername() {
        return account.getEmail(); // 또는 user.getUsername()
    }

    @Override
    public String getPassword() {
        return account.getPassword(); // 인코딩된 비밀번호
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole().name()));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // 필요시 도메인 정보에 따라 변경
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return account.isEnabled();
    }


}

