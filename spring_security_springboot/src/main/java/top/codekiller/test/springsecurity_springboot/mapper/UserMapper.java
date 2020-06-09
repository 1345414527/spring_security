package top.codekiller.test.springsecurity_springboot.mapper;

import org.apache.ibatis.annotations.*;
import tk.mybatis.mapper.common.Mapper;
import top.codekiller.test.springsecurity_springboot.pojo.SysUser;

import java.util.List;

/**
 * @author codekiller
 * @date 2020/6/8 14:21
 * @description DES
 */
public interface UserMapper extends Mapper<SysUser> {

    @Select("select * from sys_user where username=#{name}")
    @Results({
            @Result(id=true,property = "id",column = "id"),
            @Result(property = "roles",column = "id",javaType = List.class,
                    many = @Many(select = "top.codekiller.test.springsecurity_springboot.mapper.RoleMapper.findByUid"))
    })
    SysUser findByName(String name);

}
