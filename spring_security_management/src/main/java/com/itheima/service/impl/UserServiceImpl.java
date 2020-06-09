package com.itheima.service.impl;

import com.itheima.dao.UserDao;
import com.itheima.domain.SysRole;
import com.itheima.domain.SysUser;
import com.itheima.service.RoleService;
import com.itheima.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Transactional()
public class UserServiceImpl implements UserService {
    @Autowired
    private UserDao userDao;

    @Autowired
    private RoleService roleService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    /**
     * 认证用户
     *
     * @param s 用户在浏览器输入的用户名
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        try {
            //根据用户名查询
            SysUser user = this.userDao.findByName(s);
            if (user == null) {
                return null;
            }
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            List<SysRole> roles = user.getRoles();
            for (SysRole role : roles) {
                authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
            }
            //不使用加密要加{noop}
//            UserDetails userDetails=new User(user.getUsername(),"{noop}"+user.getPassword(),authorities);


            //使用加密
            UserDetails userDetails = new User(user.getUsername(), user.getPassword(), user.getStatus() == 1, true, true, true, authorities);

            return userDetails;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    @Override
    public void save(SysUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userDao.save(user);
    }

    @Override
    public List<SysUser> findAll() {
        return userDao.findAll();
    }


    @Override
    public Map<String, Object> toAddRolePage(Integer id) {
        List<SysRole> allRoles = roleService.findAll();
        List<Integer> myRoles = userDao.findRolesByUid(id);
        Map<String, Object> map = new HashMap<>();
        map.put("allRoles", allRoles);
        map.put("myRoles", myRoles);
        return map;
    }

    @Override
    public void addRoleToUser(Integer userId, Integer[] ids) {
        userDao.removeRoles(userId);
        for (Integer rid : ids) {
            userDao.addRoles(userId, rid);
        }
    }

}
