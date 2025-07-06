package com.example.back_end01.config;


import com.example.back_end01.config.formlogin.CustomUserDetailsService;
import com.example.back_end01.config.jwt.JwtAuthenticationFilter;
import com.example.back_end01.config.jwt.JwtAuthenticationSuccessHandler;
import com.example.back_end01.config.oauth2.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))//h2-console 사용
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin/login", "/h2-console/**", "/swagger-ui/**", "/v3/api-docs/**", "/account/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().authenticated()
                )
                //FormLogin
                .userDetailsService(customUserDetailsService)
                .formLogin(form -> form
                                .successHandler(jwtAuthenticationSuccessHandler)
                                .failureHandler((request, response, authentication) -> {
                                    System.out.println("formLogin failure");
                                })
                )
                //OAuth2
                .oauth2Login(oauth2 -> oauth2
                                .userInfoEndpoint(userInfo -> userInfo
                                                .userService(customOAuth2UserService)
                                )
                                .successHandler(jwtAuthenticationSuccessHandler)
                                .failureHandler((request, response, authentication) -> {
                                    System.out.println("oAuth2Login failure");
                                })
                )
//                //Firebase
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(jwt -> jwt
//                                .jwtAuthenticationConverter(firebaseConverter)
//                        )
//                )
//                // ✅ 로그인 페이지 리다이렉트 막기
//                .exceptionHandling(exception -> exception
//                        .authenticationEntryPoint((request, response, authException) -> {
//                            response.setContentType("application/json");
//                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                            response.getWriter().write("{\"error\": \"Unauthorized access\"}");
//                        })
//                        .accessDeniedHandler((request, response, accessDeniedException) -> {
//                                    response.setContentType("application/json");
//                                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//                                    response.getWriter().write("{\"error\": \"Access denied\"}");
//                        })
//                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }


}
