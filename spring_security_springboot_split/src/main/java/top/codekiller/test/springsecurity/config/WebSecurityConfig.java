package top.codekiller.test.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import top.codekiller.test.springsecurity.filter.JwtAccreditFilter;
import top.codekiller.test.springsecurity.filter.JwtVerifyFilter;
import top.codekiller.test.springsecurity.properties.JwtProperties;
import top.codekiller.test.springsecurity.service.IUserService;

/**
 * @author codekiller
 * @date 2020/6/8 11:00
 * @description DES
 */
@EnableConfigurationProperties(JwtProperties.class)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true) //开启注解
public class  WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private IUserService userService;


    @Autowired
    private JwtProperties jwtProperties;



    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 验证用户的来源[内存，数据库]
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //数据库指定
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }


    /**
     * 配置springSecurity相关信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //释放静态资源,指定资源拦截规则，指定自定义认证页面，指定退出认证配置，csrf
        http.cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/**").hasAnyRole("USER","ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .logout()
                .logoutUrl("/logout")
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .addFilter(new JwtAccreditFilter(super.authenticationManager(),this.jwtProperties))
                .addFilter(new JwtVerifyFilter(super.authenticationManager(),this.jwtProperties))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }
}
