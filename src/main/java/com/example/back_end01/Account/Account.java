package com.example.back_end01.Account;


import jakarta.persistence.*;
import lombok.*;

import java.util.HashMap;
import java.util.Map;


@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String provider; // ex) google, naver, kakao
    private String password;
    private String providerId; // 소셜 ID
    private String email;
    private String name;
    private String profileImage;
    private boolean enabled;

    @Enumerated(EnumType.STRING)
    private Role role;

    public enum Role {
        USER, ADMIN
    }


    public Map<String, Object> toClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", this.id);
        claims.put("email", this.email);
        claims.put("name", this.name);
        claims.put("role", this.role.name());
        claims.put("provider", this.provider);
        claims.put("profileImage", this.profileImage);
        return claims;
    }


}