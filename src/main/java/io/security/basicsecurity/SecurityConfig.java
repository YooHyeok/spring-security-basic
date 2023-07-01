package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
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

    @Autowired
    UserDetailsService userDetailsService; // remember me 기능을 수행할 때, 시스템에 있는 사용자 계정을 조회할때 필요한 클래스

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

        /* LogoutFilter API 설정 */
        http.logout() //로그아웃 기능이 작동한다.
                .logoutUrl("/logout") //로그아웃 처리 URL (default : /logout)
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동페이지
                .deleteCookies("JSESSIONID", "remember-me") //로그아웃 후 쿠키 삭제
                .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate(); //세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { //로그아웃 성공 후 핸들러
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                });
        /* remember - me API 설정 */
        http.rememberMe() //http대신 and() 체이닝 기법으로 연결할 수 있다.
                .rememberMeParameter("remember") // 기본 파라미터명 remember-me
                .tokenValiditySeconds(3600) // 60분  Default 14일
                .alwaysRemember(false) // 리멤버 미 기능이 활성화 되지 않아도 항상 실행(기본값 false)
                .userDetailsService(userDetailsService); // remember me 기능을 수행할 때, 시스템에 있는 사용자 계정을 조회할때 필요한 클래스이다.

        /* 동시 세션 제어 API 설정 */
        http.sessionManagement() // 세션 관리 기능이 작동한다.
                /* 세션 고정 보호 API (4개중 1개 선택; 동시 세션 제어를 꺼야 테스트가 가능함)*/
                .sessionFixation().changeSessionId() // : 새로운 세션 생성(세션 속성값 그대로 사용) 및 세션 id발급 (서블릿 3.1 이상에서 기본값 작동)
                .sessionFixation().migrateSession() // : 새로운 세션 생성(세션 속성값 그대로 사용) 및 세션 id발급 (서블릿 3.1이하에서 기본값 작동)
                .sessionFixation().newSession() // 새로운 세션 생성 및 id 발급 이전 세션에서 설정한 여러가지 속성 값들을 사용하지 못하고 새롭게 속성값을 설정해야한다.
                .sessionFixation().none() // 세션이 새롭게 생성되지 않고 세션ID도 그대로 / 세션고정 공격에 노출된다.

                /* 세션 정책 API (4개중 1개 선택)*/
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 스프링 시큐리티가 항상 세션 생성
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 스프링 시큐리티가 필요 시 세션 생성(기본값)
                .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 스프링 시큐리티가 세션을 생성하지 않지만 이미 존재하면 존재하는 세션을 사용
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 스프링 시큐리티가 세션을 생성하지도 않고 존재해도 사용하지 않음. (세션대신 JWT 인증방식)

                /* 동시 세션 제어 API */
                .invalidSessionUrl("/invalid") //세션이 유효하지 않을 때 이동할 페이지
                .maximumSessions(1) //최대 허용 가능 세선 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) //동시 로그인 차단, false: 기존 세션 만료(default)
                .expiredUrl("/expired"); //세션이 만료된 경우 이동할 페이지
                ///invalid 와 /expired 를 permitAll() 로 설정 하지 않았을 경우와 같이 해당 URL을 인증받지 못한 상태에서 접근하게 되면 /login으로 이동하게 된다.
    }
}
