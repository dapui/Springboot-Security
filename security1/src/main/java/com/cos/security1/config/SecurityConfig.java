package com.cos.security1.config;

import com.cos.security1.config.auth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

// 1. 코드받기(인증), 2. 엑세스토큰(권한)
// 3. 사용자프로필 정보를 가져오고 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
// 4-2. (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (vip등급, 일반등급)

@Configuration // SecurityConfig 클래스가 bean 메서드를 가지고 있음을 명시
@EnableWebSecurity  // 스프링 시큐리티 필터(SecurityConfig)가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // Spring Security에서 메서드 단위로 권한을 검사할 수 있도록 활성화(@Secured, @PreAuthorize & @PostAuthorize 어노테이션 활성화)
public class SecurityConfig {

    @Autowired
    PrincipalOauth2UserService principalOauth2UserService;

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
                .defaultSuccessUrl("/")) // 로그인 완료시 이동되는 페이지
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요함. Tip. 코드X (엑세스토큰+사용자프로필정보O)
                .userInfoEndpoint(endpoint -> endpoint.userService(principalOauth2UserService))
            );
        return http.build();
    }

    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }
}
