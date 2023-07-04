package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext)session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();
        return "home";
    }


    @GetMapping("/thread")
    public String thread() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            }
        });

        return "thread";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }
    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }
    @GetMapping("/admin/pay")
    public String admin_sys() {
        return "admin/sys";
    }
    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }
    @GetMapping("/login")
    public String login() {
        return "requestedLogin";
    }
}
