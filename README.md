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

7. 存入数据库

8. Spring Security + Spring Data Jpa
    8.0 引入依赖
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
    8.1 创建实体类Role和User，User要实现UserDetails接口
    8.2 在实体类标注Entity和Id
        @Entity: 表示这是一个实体类，项目启动后，将会根据实体类的属性在数据库中自动创建一个角色表
        @Id: 再加上@GeneratedValue(strategy = GenerationType.IDENTITY)，表示自增策略
    8.3 User实体类实现的方法：
        ·accountNonExpired-账户是否没有过期、accountNonLocked-账户是否没有被锁定、credentialsNonExpired-密码是否没有过期、enabled-账户是否可用。
        ·roles 属性表示用户的角色，User 和 Role 是多对多关系，用一个 @ManyToMany 注解来描述。
          @ManyToMany(fetch = FetchType.EAGER,cascade = CascadeType.PERSIST)
        ·getAuthorities 方法返回用户的角色信息，我们在这个方法中把自己的 Role 稍微转化一下即可。
    8.4 定义一个 UserDao：只需要继承 JpaRepository 然后提供一个根据 username 查询 user 的方法
        public interface UserDao extends JpaRepository<User,Long> {
            User findUserByUsername(String username);
        }
    8.5 定义 UserService：
        8.5.1 需要实现 UserDetailsService 接口，实现该接口，就要实现接口中的方法，也就是 loadUserByUsername
              这个方法的参数就是用户在登录的时候传入的用户名，根据用户名去查询用户信息（查出来之后，系统会自动进行密码比对）
        @Service
        public class UserService implements UserDetailsService {
            @Autowired
            UserDao userDao;
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                User user = userDao.findUserByUsername(username);
                if (user == null) {
                    throw new UsernameNotFoundException("用户不存在");
                }
                return user;
            }
        }
    8.6 在 Spring Security 中稍作配置
        8.6.1 在 SecurityConfig 中，我们通过如下方式来配置用户：
              @Autowired
              UserService userService;
              @Override
              protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                  auth.userDetailsService(userService);
              }
        8.6.2 注意: 还是重写configure方法，只不过这次我们不是基于内存，也不是基于JdbcUserDetailsManager，而是使用自定义的 UserService，就这样配置就 OK 了
    8.7 最后，我们再在 application.properties 中配置一下数据库和 JPA 的基本信息，如下
        spring.datasource.username=root
        spring.datasource.password=123
        spring.datasource.url=jdbc:mysql:///withjpa?useUnicode=true&characterEncoding=UTF-8&serverTimezone=Asia/Shanghai
        ## jpa
        spring.jpa.database=mysql
        spring.jpa.database-platform=mysql
        spring.jpa.hibernate.ddl-auto=update
        spring.jpa.show-sql=true
        spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL8Dialect
    8.8 测试
        @Autowired
        UserDao userDao;
        @Test
        void contextLoads() {
            User u1 = new User();
            u1.setUsername("javaboy");
            u1.setPassword("123");
            u1.setAccountNonExpired(true);
            u1.setAccountNonLocked(true);
            u1.setCredentialsNonExpired(true);
            u1.setEnabled(true);
            List<Role> rs1 = new ArrayList<>();
            Role r1 = new Role();
            r1.setName("ROLE_admin");
            r1.setNameZh("管理员");
            rs1.add(r1);
            u1.setRoles(rs1);
            userDao.save(u1);
            User u2 = new User();
            u2.setUsername("江南一点雨");
            u2.setPassword("123");
            u2.setAccountNonExpired(true);
            u2.setAccountNonLocked(true);
            u2.setCredentialsNonExpired(true);
            u2.setEnabled(true);
            List<Role> rs2 = new ArrayList<>();
            Role r2 = new Role();
            r2.setName("ROLE_user");
            r2.setNameZh("普通用户");
            rs2.add(r2);
            u2.setRoles(rs2);
            userDao.save(u2);
        }
    8.9 数据库多了会插入用户数据
    
9. 登录时加入验证码
    9.1 生成验证码工具类
    9.2 在LoginController里提供验证码的接口
    9.3 在SecurityConfig配置类里配置获取验证码接口/verifyCode免鉴权
    9.4 在Spring Security 的配置中，配置过滤器
    9.5 测试
        9.5.1 获取验证码：http://localhost:8080/verifyCode
        9.5.2 登录输入验证码：http://localhost:8080/doLogin
             
    