package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;

    @Bean // authenticationManager를 IoC에 등록해줌.
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
            .addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class) // 커스텀 필터 추가
            .csrf(AbstractHttpConfigurer::disable) // CSRF 보호 비활성화
            .sessionManagement(session -> session // session을 사용하지 않겠다 -> stateless 서버로 만든다
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .formLogin(form -> form.disable()) // form 로그인 비활성화
            .addFilter(corsConfig.corsFilter()) // 인증이 필요 없을 경우에는 컨트롤러에 @CrossOrigin, 인증이 필요한 경우에는 시큐리티 필터에 등록
            .addFilter(new JwtAuthenticationFilter(authenticationManager))
            .httpBasic(httpBasic -> httpBasic.disable()) // HTTP Basic 인증 비활성화
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN") // USER, MANAGER, ADMIN 인증이 필요
                .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN") // MANAGER, ADMIN 인증이 필요
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN") // ADMIN권한이 있는 사람만 들어올 수 있음
                .anyRequest().permitAll() // 그리고 나머지 url은 전부 권한을 허용
            );

        return http.build();
    }

}