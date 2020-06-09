package top.codekiller.test.springsecurity_springboot.service.impl;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.codekiller.test.springsecurity_springboot.mapper.UserMapper;
import top.codekiller.test.springsecurity_springboot.service.IUserService;

/**
 * @author codekiller
 * @date 2020/6/8 15:00
 * @description DES
 */
@Service
@Transactional(rollbackFor = Exception.class)
public class UserServiceImpl implements IUserService {

    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return this.userMapper.findByName(s);
    }
}
