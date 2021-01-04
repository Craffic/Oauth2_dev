package com.craffic.spring.security.oauth;

import com.craffic.spring.security.oauth.util.VerifyCodeUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

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


    /**
     * 获取验证码接口
     */
    @GetMapping("/verifyCode")
    public void getVerifyCode(HttpServletRequest req, HttpServletResponse response) throws Exception {
        VerifyCodeUtil verifyCode = new VerifyCodeUtil();
        BufferedImage image = verifyCode.getImage();
        String text = verifyCode.getText();
        HttpSession session = req.getSession();
        session.setAttribute("verify_code", text);
        VerifyCodeUtil.output(image, response.getOutputStream());
    }

}
