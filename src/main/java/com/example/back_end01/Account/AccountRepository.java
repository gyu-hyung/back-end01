package com.example.back_end01.Account;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByEmail(String email);
    Optional<Account> findByProviderAndProviderId(String provider, String providerId);
    Optional<Account> findByProviderId(String providerId);
    Optional<Account> findByProviderAndEmail(String provider, String username);
}


