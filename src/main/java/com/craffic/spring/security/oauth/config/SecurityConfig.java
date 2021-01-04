package com.craffic.spring.security.oauth.config;

import com.craffic.spring.security.oauth.Filter.LoginFilter;
import com.craffic.spring.security.oauth.Filter.VerifyCodeFilter;
import com.craffic.spring.security.oauth.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.PrintWriter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//    @Autowired
//    DataSource dataSource;

    @Autowired
    VerifyCodeFilter verifyCodeFilter;

    @Autowired
    UserService userService;
    @Bean
    PasswordEncoder passwordEncoder(){
        // 暂时使用明文存储，方法已过期必须使用加密密码
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 提供一个 LoginFilter 的实例
     * @throws Exception
     */
    @Bean
    LoginFilter loginFilter() throws Exception {
        LoginFilter loginFilter = new LoginFilter();
        loginFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                response.setContentType("application/json;charset=utf-8");
                PrintWriter writer = response.getWriter();
                writer.write(new ObjectMapper().writeValueAsString(authentication.getPrincipal()));
                writer.flush();
                writer.close();
            }
        });
        loginFilter.setAuthenticationFailureHandler(new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                response.setContentType("application/json;charset=utf-8");
                PrintWriter out = response.getWriter();
                if (exception instanceof LockedException) {
                    out.write(new ObjectMapper().writeValueAsString("账户被锁定，请联系管理员!"));
                } else if (exception instanceof CredentialsExpiredException) {
                    out.write(new ObjectMapper().writeValueAsString("密码过期，请联系管理员!"));
                } else if (exception instanceof AccountExpiredException) {
                    out.write(new ObjectMapper().writeValueAsString("账户过期，请联系管理员!"));
                } else if (exception instanceof DisabledException) {
                    out.write(new ObjectMapper().writeValueAsString("账户被禁用，请联系管理员!"));
                } else if (exception instanceof BadCredentialsException) {
                    out.write(new ObjectMapper().writeValueAsString("用户名或者密码输入错误，请重新输入!"));
                } else if(exception instanceof AuthenticationException){
                    out.write(new ObjectMapper().writeValueAsString("验证码输入错误!"));
                }
                out.flush();
                out.close();
            }
        });
        loginFilter.setAuthenticationManager(authenticationManagerBean());
        loginFilter.setFilterProcessesUrl("/doLogin");
        return loginFilter;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/images/**", "/css/**", "/verifyCode");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 添加验证码过滤器到用户名密码过滤器前面
//        http.addFilterBefore(verifyCodeFilter, UsernamePasswordAuthenticationFilter.class);
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and()
                .csrf().disable();
        http.addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class);
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
