package top.codekiller.security;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author codekiller
 * @date 2020/6/9 18:01
 * @description DES
 */

@SpringBootApplication
@MapperScan("top.codekiller.security.mapper")
public class OAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(OAuthApplication.class);
    }
}
