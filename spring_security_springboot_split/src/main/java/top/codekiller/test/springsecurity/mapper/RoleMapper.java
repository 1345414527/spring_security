package top.codekiller.test.springsecurity.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import top.codekiller.test.springsecurity.pojo.SysRole;


import java.util.List;

/**
 * @author codekiller
 * @date 2020/6/8 14:40
 * @description DES
 */

public interface RoleMapper {

    @Select("select r.id,r.role_name,r.role_desc from sys_role r,sys_user_role ur where r.id=ur.rid and ur.uid=#{uid} ")
    List<SysRole> findByUid(Integer uid);
}
