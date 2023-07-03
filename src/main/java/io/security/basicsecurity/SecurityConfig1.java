/*
package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@Order(0)
public class SecurityConfig1 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/admin/**") // /admin URL로 요청할 때만 보안기능 작동하도록 설정
            .authorizeRequests()
            .anyRequest().authenticated() //모든 사용자가 인증을 받아야만 /admin URL에 해당하는 모든 요청 자원에 접근이 가능
        .and().httpBasic(); // httpBasic 인증방식
    }
}

@Configuration
@Order(1)
class SecurityConfig2 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().permitAll() //모든 사용자가 인증을 받지 않더라도 어떠한 요청에도 보안기능이 작동하도록 설정
        .and().formLogin(); // formLogin 인증방식
    }
}*/
