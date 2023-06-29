package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Security 설정 Class <br/>
 * @@Congifuration Spring 설정 Anntation
 * @@EnableWebSecurity 웹 보안 활성화 어노테이션
 * @extends WebSecurityConfigurerAdapter
 * @@Override Protected void configure(HttpSecurity http)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     *  API 인증,인가 설정
     * WebSecurityConfigurerAdapter를 상속받아 사용자 정의 보안 기능을 구현 <br/>
     * configure 메소드를 오버라이딩 하여 원하는 보안 기능만 추가한다.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /** 인가 정책 설정 */
        http.authorizeRequests()//사용자가 http 요청을 할 때 보안 검사 시작
                .anyRequest().authenticated();// 어떠한 요청에도 인증을 받도록 API를 설정

        /** 인증 정책 설정 */
        http.formLogin();// 인증을 받지 않으면 form 로그인을 제공

    }
}
