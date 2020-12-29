package com.craffic.spring.security.oauth.config;

import com.craffic.spring.security.oauth.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
import java.io.PrintWriter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//    @Autowired
//    DataSource dataSource;
    @Autowired
    UserService userService;
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
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
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
//                .defaultSuccessUrl("/success")

                // 前后端分离，返回json数据给前端
                // 登录成功的回调
                .successHandler((res, resp, authentication) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString(authentication.getPrincipal()));
                    writer.flush();
                    writer.close();
                })
                // 登录失败的回调
                .failureHandler((res, resp, exception) -> {
                    // 根据exception告诉什么原因的失败
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString(exception.getMessage()));
                    writer.flush();
                    writer.close();
                })

                .permitAll()
                .and()
                .logout()
                // 这里的/logout是个get请求
                .logoutUrl("/logout")
                // 如果想让/logout是个post请求，可以这样来
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
                // 退出登录后跳转到登陆页面
//                .logoutSuccessUrl("/login.html")
                // 退出登录session失效
//                .invalidateHttpSession(true)
                // 清除认证信息
//                .clearAuthentication(true)

                // 注销登录
                // 如果注销登录，希望返回json字符串，而不是跳转到登陆页面
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString("注销登录成功"));
                    writer.flush();
                    writer.close();
                })


                .permitAll()
                .and()
                .csrf().disable()
                // 如果没登录就请求资源就会跳转到登录页面，在前后端分离的系统中是不行的，所以当未登录时请求系统资源返回json字符串就行
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, exception) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString("用户尚未登录，请先登录！"));
                    writer.flush();
                    writer.close();
                });
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        // 用户信息配置在内存里
////        auth.inMemoryAuthentication().withUser("Craffic").password("123456").roles("admin");
////        auth.inMemoryAuthentication().withUser("liuchengyan").password("123456").roles("user");
//    }

//    /**
//     * 自定义用户
//     */
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
////        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
//        if (!manager.userExists("Craffic")) {
//            manager.createUser(User.withUsername("Craffic").password("123456").roles("admin").build());
//        }
//        if (!manager.userExists("liuchengyan")) {
//            manager.createUser(User.withUsername("liuchengyan").password("123456").roles("user").build());
//        }
//        return manager;
//    }

    /*
   配置用户
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    /**
     * 角色继承
     * admin继承user角色
     */
    @Bean
    public RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return roleHierarchy;
    }
}
