import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import top.codekiller.test.springsecurity.SpringSecurityApplication;
import top.codekiller.test.springsecurity.config.WebSecurityConfig;

/**
 * @author codekiller
 * @date 2020/6/8 21:39
 * @description DES
 */
@SpringBootTest(classes = SpringSecurityApplication.class)
class Test1 {

    @Autowired
    WebSecurityConfig webSecurityConfig;

    @Test
    public void test1(){
        System.out.println("springse"+webSecurityConfig);
    }
}
