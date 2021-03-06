package top.codekiller.test.springsecurity_springboot.mapper;

import org.apache.ibatis.annotations.Select;
import top.codekiller.test.springsecurity_springboot.pojo.SysRole;

import java.util.List;

/**
 * @author codekiller
 * @date 2020/6/8 14:40
 * @description DES
 */
public interface RoleMapper {

    @Select("select r.id,r.role,r.role_name roleName,r.role_desc roleDesc from sys_role r,sys_user_role ur where r.id=ur.rid and ur.uid=#{uid} ")
    List<SysRole> findByUid(Integer uid);
}
