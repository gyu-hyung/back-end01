package com.example.back_end01.config.firebase;

import com.example.back_end01.Account.Account;
import com.example.back_end01.Account.AuthenticatedAccount;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

public class FirebaseUserPrincipal implements AuthenticatedAccount {

    private final Account account;

    public FirebaseUserPrincipal(Account account) {
        this.account = account;
    }

    @Override
    public Account getAccount() {
        return account;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole().name()));
    }
}

