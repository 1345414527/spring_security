package top.codekiller.test.springsecurity.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import top.codekiller.test.springsecurity.pojo.SysRole;
import top.codekiller.test.springsecurity.pojo.SysUser;
import top.codekiller.test.springsecurity.properties.JwtProperties;
import top.codekiller.test.springsecurity.utils.JsonUtils;
import top.codekiller.test.springsecurity.utils.JwtUtils;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author codekiller
 * @date 2020/6/8 19:17
 * @description 登录过滤器
 */
@Slf4j
public class JwtAccreditFilter extends UsernamePasswordAuthenticationFilter {


    private AuthenticationManager authenticationManager;

    private JwtProperties jwtProperties;

    private ObjectMapper objectMapper=new ObjectMapper();

    public JwtAccreditFilter(AuthenticationManager authenticationManager, JwtProperties jwtProperties) {
        this.authenticationManager = authenticationManager;
        this.jwtProperties = jwtProperties;
    }


    /**
     * 接受并解析用户凭证
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            SysUser sysUser = objectMapper.readValue(request.getInputStream(), SysUser.class);
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(sysUser.getUsername(), sysUser.getPassword());
            return this.authenticationManager.authenticate(authRequest);
        } catch (IOException e) {
            PrintWriter writer=null;
            try {
                response.setContentType("application/json;charset=utf-8");
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                writer= response.getWriter();
                Map<String,Object> map=new HashMap<>(16);
                map.put("result_code",HttpStatus.UNAUTHORIZED.value());
                map.put("result_reason","用户名或者密码错误");
                writer.write(JsonUtils.serialize(map));
                writer.flush();
            } catch (IOException ex) {
                log.error("登录出错",e);
            }finally {
                if(writer!=null){
                    writer.close();
                }
            }

            throw  new RuntimeException(e);
        }
    }

    /**
     * 进行授权
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        SysUser user=new SysUser();
        user.setUsername(authResult.getName());
        user.setRoles((List<SysRole>)authResult.getAuthorities());

        try {
            String token = JwtUtils.generateTokenExpireInMinutes(user, this.jwtProperties.getPrivateKey(), this.jwtProperties.getExpire()*60);
            response.addHeader(this.jwtProperties.getHeaderName(), "Bearer " + token);
        } catch (Exception e) {
            PrintWriter writer=null;
            try {
                response.setContentType("application/json;charset=utf-8");
                response.setStatus(HttpStatus.OK.value());
                writer= response.getWriter();
                Map<String,Object> map=new HashMap<>(16);
                map.put("result_code",HttpStatus.OK.value());
                map.put("result_reason","认证通过");
                writer.write(JsonUtils.serialize(map));
                writer.flush();
            } catch (IOException ex) {
                log.error("授权失败",e);
            }finally {
                if(writer!=null){
                    writer.close();
                }
            }

            throw  new RuntimeException(e);
        }
    }


}
