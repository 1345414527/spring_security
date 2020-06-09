package top.codekiller.springsecurity;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author codekiller
 * @date 2020/6/8 22:48
 * @description DES
 */
@SpringBootApplication
@MapperScan("top.codekiller.springsecurity.mapper")
public class SpringSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class);
    }
}
