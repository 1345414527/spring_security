package top.codekiller.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import top.codekiller.springsecurity.filter.JwtVerifyFilter;
import top.codekiller.springsecurity.properties.JwtProperties;


/**
 * @author codekiller
 * @date 2020/6/8 11:00
 * @description springsecurity配置类
 */
@EnableConfigurationProperties(JwtProperties.class)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true) //开启注解
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private JwtProperties jwtProperties;


    /**
     * 配置springSecurity相关信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //指定资源拦截规则,指定退出认证配置，csrf
        http.cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/product").hasAnyRole("ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .addFilter(new JwtVerifyFilter(super.authenticationManager(),this.jwtProperties))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }
}
