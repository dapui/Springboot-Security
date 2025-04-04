package com.cos.jwt.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음.
 * /login 요청해서 username, password 전송하면(post)
 * UsernamePasswordAuthenticationFilter 동작함
 * SecurityCongig에 .formLogin(form -> form.disable()) 설정하면 UsernamePasswordAuthenticationFilter가 동작하지 않음.
 * UsernamePasswordAuthenticationFilter가 다시 동작하게 하려면 SecurityCongig에 JwtAuthenticationFilter를 등록해준다
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        // 1. username, password 받아서

        // 2. 정상인지 로그인 시도를 한다. authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService가 호 -> loadUserByUsername() 함수가 실행됨

        // 3.PrincipalDetails를 세션에 담고(권한 관리를 위해서)

        // 4. JWT토큰을 만들어서 응답해주면 됨

        return super.attemptAuthentication(request, response);
    }


}
