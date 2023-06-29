package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Security 설정 Class <br/>
 * @@Congifuration Spring 설정 Anntation
 * @@EnableWebSecurity 웹 보안 활성화 어노테이션
 * @extends WebSecurityConfigurerAdapter
 * @@Override Protected void configure(HttpSecurity http)
 *  <a href="u2ful.tistory.com/35">successHandler빈등록법</a>
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
        http.formLogin()// Form 로그인 인증 기능 작동 (인증을 받지 않으면 form 로그인을 제공)
//                .loginPage("/loginPage") // 사용자 정의 로그인 페이지 설정(누구나 로그인 할 수 있도록 접근 가능)
                .defaultSuccessUrl("/") //로그인 성공 후 이동 페이지 설정
                .failureUrl("/login") //로그인 실패 후 이동 페이지 설정
                .usernameParameter("userId") //<Form>으로 전송하는 username 정보를 담은 파라미터명 설정
                .passwordParameter("passwd") //<Form>으로 전송하는 password 정보를 담은 파라미터명 설정
                .loginProcessingUrl("/sign_in") // 로그인 요청을 처리 하는 컨트롤러 매핑 주소 설정
                .successHandler(new AuthenticationSuccessHandler() { //로그인 성공 후 핸들러 설정
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication = " + authentication.getName()); // 인증에 성공한 사용자 이름 출력
                        response.sendRedirect("/"); //메인 Url Redirect
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { //로그인 실패 후 핸들러 설정
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception = " + exception.getMessage()); // 인증 실패 예외 메시지 출력
                        response.sendRedirect("/login"); //로그인 Url Redirect
                    }
                })
                .permitAll(); //loginPage()에 지정한 "/loginPage" URL을 누구나 접근 가능하도록 허용한다.
    }
}
