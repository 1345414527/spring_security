package top.codekiller.test.springsecurity.mapper;

import org.apache.ibatis.annotations.*;
import org.mybatis.spring.annotation.MapperScan;
import top.codekiller.test.springsecurity.pojo.SysUser;

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
                    many = @Many(select = "top.codekiller.test.springsecurity.mapper.RoleMapper.findByUid"))
    })
    SysUser findByName(String name);

}
