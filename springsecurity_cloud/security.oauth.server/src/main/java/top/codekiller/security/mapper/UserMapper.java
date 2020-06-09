package top.codekiller.security.mapper;

import org.apache.ibatis.annotations.Many;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import top.codekiller.security.pojo.SysUser;

import java.util.List;

/**
 * @author codekiller
 * @date 2020/6/8 14:21
 * @description DES
 */

public interface UserMapper  {

    @Select("select * from sys_user where username=#{name}")
    @Results({
            @Result(id=true,property = "id",column = "id"),
            @Result(property = "roles",column = "id",javaType = List.class,
                    many = @Many(select = "top.codekiller.security.mapper.RoleMapper.findByUid"))
    })
    SysUser findByName(String name);

}
