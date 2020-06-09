package top.codekiller.test.springsecurity_springboot;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * @author codekiller
 * @date 2020/6/8 11:41
 * @description DES
 */
public class ServletInitializer extends SpringBootServletInitializer {
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(SpringsecuritySpringbootApplication.class);
    }
}
