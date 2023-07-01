package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index() {
        return "home";
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
}
