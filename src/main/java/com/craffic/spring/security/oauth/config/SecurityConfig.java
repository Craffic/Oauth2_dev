package com.craffic.spring.security.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder(){
        // 暂时使用明文存储，方法已过期必须使用加密密码
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/images/**", "/css/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
                .usernameParameter("name")
                .passwordParameter("passwd")
                // 前后端不分离的回调
                // 登录成功后的一个跳转默认地址，服务端的跳转
                // 登录后跳转到localhost:8080.报404错误，因为没有/这个路径，登陆成功后有个默认路径跳转到/
                // 自己定义一个success页面, 登陆成功后跳转到/success页面上，但是路径还是http://localhost:8080/doLogin，说明他是个服务端跳转
                // successForwardUrl有个特点就是：不管从什么页面过来的，登录成功后都是跳转到/success页面上来
//                .successForwardUrl("/success")
                // 还有一个就是defaultSuccessUrl，会记住你原始跳转时重定向的url
                // 比如京东淘宝没登录就允许加入购物车，但是结算的时候要让你登录，登录成功后就是结算页面，而不是首页，说明登录时记录了你重定向的地址
                // 登录成功后，地址变成http://localhost:8080/success，说明重定向成功了
                // 登录前输入hello路径，登录后会跳转到hello路径
                // defaultSuccessUrl(url, false) = successForwardUrl
                .defaultSuccessUrl("/success")
                .permitAll()
                .and()
                .logout()
                // 这里的/logout是个get请求
                .logoutUrl("/logout")
                // 如果想让/logout是个post请求，可以这样来
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
                // 退出登录后跳转到登陆页面
                .logoutSuccessUrl("/login.html")
                // 退出登录session失效
                .invalidateHttpSession(true)
                // 清除认证信息
                .clearAuthentication(true)
                .permitAll()
                .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 用户信息配置在内存里
        auth.inMemoryAuthentication().withUser("Craffic").password("123456").roles("admin");
    }
}
