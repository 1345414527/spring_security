package top.codekiller.test.springsecurity.pojo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

@Data
public class SysRole implements GrantedAuthority {
    private Integer id;
    private String roleName;
    private String roleDesc;


    @JsonIgnore
    @Override
    public String getAuthority() {
        return this.roleName;
    }
}
