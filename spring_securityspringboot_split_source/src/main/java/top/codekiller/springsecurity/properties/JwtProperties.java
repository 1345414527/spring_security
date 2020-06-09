package top.codekiller.springsecurity.properties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import top.codekiller.springsecurity.utils.RsaUtils;

import javax.annotation.PostConstruct;
import java.security.PublicKey;

/**
 * @author codekiller
 * @date 2020/5/27 0:30
 * @description token配置类
 */

@ConfigurationProperties(prefix = "manager.jwt")
@Slf4j
@Data
public class JwtProperties {


    /**
     * 公钥
     */
    private PublicKey publicKey;

    /**
     * 公钥地址
     */
    private String pubKeyPath;


    /**
     * token的请求头名称
     */
    private String headerName;


    @PostConstruct
    public void init(){
        try {
            // 获取私钥
            this.publicKey = RsaUtils.getPublicKey(pubKeyPath);
        } catch (Exception e) {
            log.error("初始化公钥失败！", e);
            throw new RuntimeException();
        }
    }


}
