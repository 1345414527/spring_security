package top.codekiller.test.springsecurity_springboot.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import top.codekiller.test.springsecurity_springboot.service.IUserService;

/**
 * @author codekiller
 * @date 2020/6/8 11:00
 * @description DES
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true,jsr250Enabled = true,prePostEnabled = true) //开启三种方式的注解
public class springSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private IUserService userService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 验证用户的来源[内存，数据库]
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //内存指定
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}123")
                .roles("USER","ADMIN");    //不要加前缀，ROLE_USER=>USER

        //数据库指定
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }


    //配置springSecurity相关信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //释放静态资源,指定资源拦截规则，指定自定义认证页面，指定退出认证配置，csrf
        http.authorizeRequests()
                .antMatchers("/login.jsp","/failer.jsp","/css/**","/img/**","/plugin/**").permitAll()
                .antMatchers("/**").hasAnyRole("USER","ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login.jsp")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/index.jsp")
                .failureForwardUrl("/failer.jsp")
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login.jsp")
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .csrf()
                .disable();
        System.out.println("dsa");
    }
}
