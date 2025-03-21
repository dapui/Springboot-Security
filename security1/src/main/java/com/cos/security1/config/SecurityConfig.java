package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // SecurityConfig 클래스가 bean 메서드를 가지고 있음을 명시
@EnableWebSecurity  // 스프링 시큐리티 필터(SecurityConfig)가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // Spring Security에서 메서드 단위로 권한을 검사할 수 있도록 활성화(@Secured, @PreAuthorize & @PostAuthorize 어노테이션 활성화)
public class SecurityConfig {

    // 보안 설정 구성
    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").authenticated() // user라는 url로 들어오면 인증이 필요
                .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN") // manager로 들어오면 MANAGER 또는 ADMIN 인증이 필요
                .requestMatchers("/admin/**").hasRole("ADMIN") // admin으로 들어오면 ADMIN권한이 있는 사람만 들어올 수 있음
                .anyRequest().permitAll() // 그리고 나머지 url은 전부 권한을 허용
            )
            .formLogin(form -> form
                .loginPage("/loginForm") // 기본 로그인 폼 활성화
                .loginProcessingUrl("/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행
                .defaultSuccessUrl("/")); // 로그인 완료시 이동되는 페이지
        return http.build();
    }

    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }
}
