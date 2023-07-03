package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

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
     * 사용자를 생성하고 권한을 설정한다. <br/>
     * AuthenticationManagerBuilder : 사용자 생성, 권한 설정 제공
     * @param auth the {@link AuthenticationManagerBuilder} to use
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER"); // 메모리 방식으로 사용자를 생성
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1234").roles("SYS"); // {noop} 평문으로 암호화 - prefix형태로 암호화 알고리즘 유형 지정
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN");
    }

    /**
     *  API 인증,인가 설정
     * WebSecurityConfigurerAdapter를 상속받아 사용자 정의 보안 기능을 구현 <br/>
     * configure 메소드를 오버라이딩 하여 원하는 보안 기능만 추가한다.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /* 인가 정책 API */
//        authorizeRequests(http); //인가 정책 API
        /** 인증 정책 설정 */
//        formLogin(http);
        /* LogoutFilter API 설정 */
//        logOut(http);
        /* remember - me API 설정 */
//        rememberMe(http);
        /* 동시 세션 제어 API */
//        sessionManagement(http);
        /* 인증 & 인가 예외처리 API */
//        exceptionHandling(http);

//        사용자_정의_보안_기능_구현(http);
//        formLogin_인증_기능_구현(http);
//        logout_기능_구현(http);
//        rememberMe_인증_기능_구현(http);
//        동시_세션_제어_API_기능_구현(http);
//        세션_고정_보호_API_기능_구현(http);
//        세션_정책_API_기능_구현(http);
//        권한설정과_표현식_기능_구현(http);
//        예외처리_및_요청_캐시(http);
        securityContextThreadLocal(http);
    }

    private static void securityContextThreadLocal(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin();
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    private static void 예외처리_및_요청_캐시(HttpSecurity http) throws Exception {
        /** 인가 정책 설정 */
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .antMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                .anyRequest().authenticated();
        http.formLogin()
                .successHandler(new AuthenticationSuccessHandler() { //로그인 성공 후 핸들러 설정
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication = " + authentication.getName());

                        /* 인증 & 인가 예외 처리 - 인증 성공 후 원래 가려고 했던 경로로 이동 */
                        RequestCache requestCache = new HttpSessionRequestCache(); // 인증 예외 발생 후 해당 요청에 대한 세션 정보를 담은 캐시 객체
                        SavedRequest savedRequest = requestCache.getRequest(request, response); // 원래 사용자가 가고자 했던 요청정보가 저장되어 있다.
                        String redirectUrl = savedRequest.getRedirectUrl(); //원래 사용자가 가고자했던 요청 URL
                        response.sendRedirect(redirectUrl);

//                        response.sendRedirect("/"); //메인 Url Redirect
                    }
                });

        /* Exception 핸들링 */
        http.exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() { //인증 예외 발생 처리
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login"); // 인증 예외 발생 후 이동할 페이지 (시큐리티가 아닌 직접 등록한 REST API)
                        // /login은 인증 자체를 받지 않은 사용자가 이동하는 url이므로 antMatchers()를 등록해야한다.

                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { //인가 예외 발생 처리
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied"); // 인가 예외 발생 후 이동할 페이지 (시큐리티가 아닌 직접 등록한 REST API)
                        // 현재 사용자가 접근하고자 하는 자원에 접근할 수 있는 '권한' 자체가 맞지 않는 예외이다.(인증을 받은 사용자)
                    }
                });
    }

    private static void 권한설정과_표현식_기능_구현(HttpSecurity http) throws Exception {
        /** 인가 정책 설정 */
        http.authorizeRequests()//사용자가 http 요청을 할 때 보안 검사 시작
                /* 권한 API 설정 */
                //현재 사용자가 /user요청을 하게 되면 권한심사를 통해서 권한이 USER인 사용자만 해당 url자원에 접근가능하도록 인가처리를 한다.
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                //admin을 포함한 모든 경로에 대한 요청에 ADMIN, SYS 사용자만이 해당 URL 접근 가능하도록 인가처리.
                .antMatchers("/admin/pay").hasRole("ADMIN") // 구체적인 좁은 범위를 항상 먼저 설정한다. ex)/admin/**와 같이 넓은 범위가 먼저 오면 좁은 범위도 포함하기 때문이다.
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .antMatchers("/admin/**").hasAnyRole("ADMIN", "SYS") // 표현식 대신 이렇게도 사용 가능
                .anyRequest().authenticated();// 어떠한 요청에도 인증을 받도록 API를 설정
    }
    private static void 세션_정책_API_기능_구현(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin();

        http.sessionManagement() // 세션 관리 기능이 작동한다.
                /* 세션 정책 API (4개중 1개 선택)*/
//                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 스프링 시큐리티가 항상 세션 생성
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 스프링 시큐리티가 필요 시 세션 생성(기본값)
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 스프링 시큐리티가 세션을 생성하지 않지만 이미 존재하면 존재하는 세션을 사용
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 스프링 시큐리티가 세션을 생성하지도 않고 존재해도 사용하지 않음. (세션대신 JWT 인증방식)

    }
    private static void 세션_고정_보호_API_기능_구현(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin();

        http.sessionManagement() // 세션 관리 기능이 작동한다.
                /* 세션 고정 보호 API (4개중 1개 선택; 동시 세션 제어를 꺼야 테스트가 가능함)*/
                .sessionFixation().changeSessionId(); // : 새로운 세션 생성(세션 속성값 그대로 사용) 및 세션 id발급 (서블릿 3.1 이상에서 기본값 작동)
//                .sessionFixation().migrateSession() // : 새로운 세션 생성(세션 속성값 그대로 사용) 및 세션 id발급 (서블릿 3.1이하에서 기본값 작동)
//                .sessionFixation().newSession() // 새로운 세션 생성 및 id 발급 이전 세션에서 설정한 여러가지 속성 값들을 사용하지 못하고 새롭게 속성값을 설정해야한다.
//                .sessionFixation().none() // 세션이 새롭게 생성되지 않고 세션ID도 그대로 / 세션고정 공격에 노출된다.

    }
    private static void 동시_세션_제어_API_기능_구현(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin();

        http.sessionManagement()
                /* 동시 세션 제어 API */
                .invalidSessionUrl("/invalid") //세션이 유효하지 않을 때 이동할 페이지
                .maximumSessions(1) //최대 허용 가능 세선 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) //동시 로그인 차단, false: 기존 세션 만료(default)
                .expiredUrl("/expired"); //세션이 만료된 경우 이동할 페이지
        ///invalid 와 /expired 를 permitAll() 로 설정 하지 않았을 경우와 같이 해당 URL을 인증받지 못한 상태에서 접근하게 되면 /login으로 이동하게 된다.
        /* 인증 & 인가 예외처리 API */
        http.exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() { //인증 예외 발생 처리
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login"); // 인증 예외 발생 후 이동할 페이지 (시큐리티가 아닌 직접 등록한 REST API)
                        // /login은 인증 자체를 받지 않은 사용자가 이동하는 url이므로 antMatchers()를 등록해야한다.

                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { //인가 예외 발생 처리
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied"); // 인가 예외 발생 후 이동할 페이지 (시큐리티가 아닌 직접 등록한 REST API)
                        // 현재 사용자가 접근하고자 하는 자원에 접근할 수 있는 '권한' 자체가 맞지 않는 예외이다.(인증을 받은 사용자)
                    }
                });
    }

    private void rememberMe_인증_기능_구현(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin();
        http.logout() //로그아웃 기능이 작동한다.
                .logoutUrl("/logout") //로그아웃 처리 URL (default : /logout)
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동페이지
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
        /* rememberMe API 기능 구현 */
        http.rememberMe() //http대신 and() 체이닝 기법으로 연결할 수 있다.
                .rememberMeParameter("remember") // 기본 파라미터명 remember-me
                .tokenValiditySeconds(3600) // 60분  Default 14일
                .alwaysRemember(false) // 리멤버 미 기능이 활성화 되지 않아도 항상 실행(기본값 false)
                .userDetailsService(userDetailsService); // remember me 기능을 수행할 때, 시스템에 있는 사용자 계정을 조회할때 필요한 클래스이다.
    }

    private static void logout_기능_구현(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin();

        /* logout API 기능구현*/
        http.logout() //로그아웃 기능이 작동한다.
                .logoutUrl("/logout") //로그아웃 처리 URL (default : /logout)
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동페이지
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
    }

    private static void formLogin_인증_기능_구현(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin()
                .loginPage("/loginPage") // 사용자 정의 로그인 페이지 설정(누구나 로그인 할 수 있도록 접근 가능)
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

    private static void 사용자_정의_보안_기능_구현(HttpSecurity http) throws Exception {
        http.authorizeRequests()//사용자가 http 요청을 할 때 보안 검사 시작
                .anyRequest().authenticated();// 어떠한 요청에도 인증을 받도록 API를 설정
        http.formLogin(); //로그인 기능(화면)을 제공해준다.
        /*http.authorizeRequests()
                .anyRequest().authenticated()
        .and().formLogin();*/
    }

    private static void exceptionHandling(HttpSecurity http) throws Exception {
        /* 인증 & 인가 예외처리 API */
        http.exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() { //인증 예외 발생 처리
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login"); // 인증 예외 발생 후 이동할 페이지 (시큐리티가 아닌 직접 등록한 REST API)
                        // /login은 인증 자체를 받지 않은 사용자가 이동하는 url이므로 antMatchers()를 등록해야한다.

                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { //인가 예외 발생 처리
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied"); // 인가 예외 발생 후 이동할 페이지 (시큐리티가 아닌 직접 등록한 REST API)
                        // 현재 사용자가 접근하고자 하는 자원에 접근할 수 있는 '권한' 자체가 맞지 않는 예외이다.(인증을 받은 사용자)
                    }
                });
    }

    private static void sessionManagement(HttpSecurity http) throws Exception {
        /* 동시 세션 제어 API 설정 */
        http.sessionManagement() // 세션 관리 기능이 작동한다.
                /* 세션 고정 보호 API (4개중 1개 선택; 동시 세션 제어를 꺼야 테스트가 가능함)*/
                .sessionFixation().changeSessionId() // : 새로운 세션 생성(세션 속성값 그대로 사용) 및 세션 id발급 (서블릿 3.1 이상에서 기본값 작동)
//                .sessionFixation().migrateSession() // : 새로운 세션 생성(세션 속성값 그대로 사용) 및 세션 id발급 (서블릿 3.1이하에서 기본값 작동)
//                .sessionFixation().newSession() // 새로운 세션 생성 및 id 발급 이전 세션에서 설정한 여러가지 속성 값들을 사용하지 못하고 새롭게 속성값을 설정해야한다.
//                .sessionFixation().none() // 세션이 새롭게 생성되지 않고 세션ID도 그대로 / 세션고정 공격에 노출된다.

                /* 세션 정책 API (4개중 1개 선택)*/
//                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 스프링 시큐리티가 항상 세션 생성
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 스프링 시큐리티가 필요 시 세션 생성(기본값)
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 스프링 시큐리티가 세션을 생성하지 않지만 이미 존재하면 존재하는 세션을 사용
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 스프링 시큐리티가 세션을 생성하지도 않고 존재해도 사용하지 않음. (세션대신 JWT 인증방식)

                /* 동시 세션 제어 API */
//                .invalidSessionUrl("/invalid") //세션이 유효하지 않을 때 이동할 페이지
//                .maximumSessions(1) //최대 허용 가능 세선 수, -1 : 무제한 로그인 세션 허용
//                .maxSessionsPreventsLogin(true) //동시 로그인 차단, false: 기존 세션 만료(default)
//                .expiredUrl("/expired"); //세션이 만료된 경우 이동할 페이지
                // /invalid 와 /expired 를 permitAll() 로 설정 하지 않았을 경우와 같이 해당 URL을 인증받지 못한 상태에서 접근하게 되면 /login으로 이동하게 된다.
    }

    private void rememberMe(HttpSecurity http) throws Exception {
        /* remember - me API 설정 */
        http.rememberMe() //http대신 and() 체이닝 기법으로 연결할 수 있다.
                .rememberMeParameter("remember") // 기본 파라미터명 remember-me
                .tokenValiditySeconds(3600) // 60분  Default 14일
                .alwaysRemember(false) // 리멤버 미 기능이 활성화 되지 않아도 항상 실행(기본값 false)
                .userDetailsService(userDetailsService); // remember me 기능을 수행할 때, 시스템에 있는 사용자 계정을 조회할때 필요한 클래스이다.
    }

    private static void logOut(HttpSecurity http) throws Exception {
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
    }

    private static void formLogin(HttpSecurity http) throws Exception {
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

    private static void authorizeRequests(HttpSecurity http) throws Exception {
        /** 인가 정책 설정 */
        http.authorizeRequests()//사용자가 http 요청을 할 때 보안 검사 시작
                .anyRequest().authenticated();// 어떠한 요청에도 인증을 받도록 API를 설정
    }
}
