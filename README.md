# Oauth2_dev
从头学起OAuth2，学习松哥的OAuth2教程

1. 最基本的表单登录
    1.1 创建项目
    1.2 创建登录接口
    1.3 启动项目，生成默认密码
    1.4 登录创建的接口

2. 用户配置
    2.1 配置文件
        2.1.1 在配置文件application.properties里配置用户名和密码
        2.1.2 在SecurityProperties.class类里定义了spring.security前缀，而且要注入静态内部内User里
        2.1.3 重启登录，就可以使用自定义的用户名密码了
        
3. 自定义登录表单
    3.1 服务端定义
        3.1.1 在SecurityConfig 类重写configure(HttpSecurity http)方法
              设置登录页面和角色权限等。
        3.1.2 在SecurityConfig 类重写configure(HttpSecurity http)方法
              用来放行静态资源文件
        3.1.3 把login.html和静态资源复制到resources/static路径下
        3.1.4 登陆页面
        3.1.5 登录, 访问 localhost:8080/hello

4. 定制 Spring Security 中的表单登录
    4.1 登录接口
        .loginPage("/login.html")
        .loginProcessingUrl("/doLogin")
    4.2 登录参数
        .usernameParameter("name")
        .passwordParameter("passwd")
    4.3 登录回调
        ·前后端分离登录
        ·前后端不分登录
        4.3.1 登录成功回调
              · defaultSuccessUrl
              · successForwardUrl
        4.3.2 登录失败回调
              与登录成功相似，登录失败也是有两个方法：
              · failureForwardUrl：是登录失败之后会发生服务端跳转
              · failureUrl：则在登录失败之后，会发生重定向
        4.3.3 注销登录
              注销登录的默认接口是 /logout，我们也可以配置
              · logoutSuccessUrl 表示注销成功后要跳转的页面
              · deleteCookies 用来清除 cookie
              · clearAuthentication 和 invalidateHttpSession 分别表示清除认证信息和使 HttpSession 失效，默认可以不用配置，默认就会清除。
              
              
5. Oauth2做前后端分离的登录交互
    5.1 登录交互
        5.1.1 登录成功
              · defaultSuccessUrl和successForwardUrl都是配置跳转地址的，适用于前后端不分的开发。
              · 除了这两个方法之外，还有一个必杀技，那就是 successHandler。
               .successHandler((req, resp, authentication) -> {
                   Object principal = authentication.getPrincipal();
                   resp.setContentType("application/json;charset=utf-8");
                   PrintWriter out = resp.getWriter();
                   out.write(new ObjectMapper().writeValueAsString(principal));
                   out.flush();
                   out.close();
               })            
              
        5.1.2 登录失败
              .failureHandler((req, resp, e) -> {
                  resp.setContentType("application/json;charset=utf-8");
                  PrintWriter out = resp.getWriter();
                  out.write(e.getMessage());
                  out.flush();
                  out.close();
              })  
    5.2 未认证处理方案
        .csrf().disable().exceptionHandling()
        .authenticationEntryPoint((req, resp, authException) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("尚未登录，请先登录");
                    out.flush();
                    out.close();
                }
        );
    5.3 注销登录
        .and()
        .logout()
        .logoutUrl("/logout")
        .logoutSuccessHandler((req, resp, authentication) -> {
            resp.setContentType("application/json;charset=utf-8");
            PrintWriter out = resp.getWriter();
            out.write("注销成功");
            out.flush();
            out.close();
        })
        .permitAll()
        .and()


6. OAuth2用户授权
    6.1 授权
    6.2 准备测试用户（两种方式）
        6.2.1 在原来基础上添加用户
        6.2.2 重写UserDetailService类来维护用户
    6.3 准备测试接口
        6.3.1 /hello 认证后的用户都可以访问
        6.3.2 /user/hello 具有user身份的用户才可以访问
        6.3.3 /admin/hello 具有admin身份的用户才可以访问
    6.4 配置
        在http的configuration方法上增加权限配置：
            .antMatchers("/admin/**").hasRole("admin")
            .antMatchers("/user/**").hasRole("user")
    6.5 启动测试
        6.5.1 admin能访问/admin/hello和/hello接口
        6.5.2 user能访问/user/hello和/hello接口
        6.5.3 /hello接口认证过的用户都能登录
    6.6 角色继承
        admin角色的用户自动有user的角色
        @Bean
        public RoleHierarchy roleHierarchy(){
            RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
            roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
            return roleHierarchy;
        }
