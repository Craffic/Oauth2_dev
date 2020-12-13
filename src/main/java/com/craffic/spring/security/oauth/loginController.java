package com.craffic.spring.security.oauth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class loginController {

    @GetMapping("/hello")
    public String hello(){
        return "hello Oauth2";
    }

    @PostMapping("/login")
    public String login(){
        return "welcome！";
    }

    @RequestMapping("/success")
    public String success(String name, String passwd){
        return "welcome！login success!";
    }

    /**
     * admin
     */
    @RequestMapping("/admin/hello")
    public String admin(){
        return "admin role";
    }

    /**
     * user
     */
    @RequestMapping("/user/hello")
    public String user(){
        return "user role";
    }

}
