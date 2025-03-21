package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  // 스프링 시큐리티 필터(SecurityConfig)가 스프링 필터체인에 등록이 됨
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").authenticated() // user라는 url로 들어오면 인증이 필요
                .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN") // manager로 들어오면 MANAGER 또는 ADMIN 인증이 필요
                .requestMatchers("/admin/**").hasRole("ADMIN") // admin으로 들어오면 ADMIN권한이 있는 사람만 들어올 수 있음
                .anyRequest().permitAll() // 그리고 나머지 url은 전부 권한을 허용
            )
            .formLogin(form -> form
                .loginPage("/login")); // 기본 로그인 폼 활성화
        return http.build();
    }
}
