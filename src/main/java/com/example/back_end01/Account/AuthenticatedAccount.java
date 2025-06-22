package com.example.back_end01.Account;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface AuthenticatedAccount {
    Account getAccount();
    Collection<? extends GrantedAuthority> getAuthorities();
}
