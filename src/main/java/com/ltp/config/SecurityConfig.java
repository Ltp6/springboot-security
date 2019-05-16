package com.ltp.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @projectName springboot-security
 * @ClassName SecurityConfig
 * @Auther Ltp
 * @Date 2019/5/14 20:53
 * @Description 安全框架配置类
 * @Version 1.0
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * @return void
     * @Author Ltp
     * @Description 定制请求授权规则
     * @Date 2019/5/14 21:13
     * @Param [http]
     **/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //定制请求授权规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //开启自动配置的登录功能，如果没有登录，没有权限，就来到登录页面
        http.formLogin().loginPage("/userlogin");
        //开启自动配置的注销功能，注销成功后返回首页
        http.logout().logoutSuccessUrl("/");
        //开启记住我功能
        //登录成功以后，将cookie发给浏览器保存，以后访问页面带上这个cookie，只要通过检查就可以免登录，点击注销会删除cookie
        http.rememberMe().rememberMeParameter("remember");

    }

    /**
     * @return void
     * @Author Ltp
     * @Description 定义用户名、密码角色
     * @Date 2019/5/14 21:14
     * @Param [auth]
     **/
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("root").password(new BCryptPasswordEncoder().encode("ltp")).roles("VIP1", "VIP2", "VIP3")
                .and()
                .withUser("ltp").password(new BCryptPasswordEncoder().encode("ltp")).roles("VIP1")
                .and()
                .withUser("jugg").password(new BCryptPasswordEncoder().encode("ltp")).roles("VIP2", "VIP3");
    }
}
