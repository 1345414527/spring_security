package top.codekiller.test.springsecurity.filter;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import top.codekiller.test.springsecurity.pojo.SysUser;
import top.codekiller.test.springsecurity.properties.JwtProperties;
import top.codekiller.test.springsecurity.utils.JsonUtils;
import top.codekiller.test.springsecurity.utils.JwtUtils;
import top.codekiller.test.springsecurity.utils.Payload;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author codekiller
 * @date 2020/6/8 20:18
 * @description 验证过滤器
 */

@Slf4j
public class JwtVerifyFilter extends BasicAuthenticationFilter {
    private JwtProperties jwtProperties;

    public JwtVerifyFilter(AuthenticationManager authenticationManager, JwtProperties jwtProperties) {
        super(authenticationManager);
        this.jwtProperties = jwtProperties;
    }


    /**
     * 进行认证
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
       String header=request.getHeader("Authorization");

       //如果没有认证
       if(StringUtils.isBlank(header)){
           chain.doFilter(request,response);
           this.responseJson(response);

       }else{
           //携带正确格式的token
           String token = header.replace("Bearer ", "");
           System.out.println("token"+token);
           try {
               Payload<SysUser> payload = JwtUtils.getInfoFromToken(token, this.jwtProperties.getPublicKey(),SysUser.class);
               SysUser user=payload.getUserInfo();

               if(user!=null){
                   UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(user.getUsername(),null,user.getRoles());
                   SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                   chain.doFilter(request,response);
               }

           } catch (Exception e) {
               log.error("认证出错",e);
           }

       }

    }


    /**
     * 认证失败响应的json
     * @param response
     */
    private void responseJson(HttpServletResponse response) {
        PrintWriter writer=null;
        try {
            response.setContentType("application/json;charset=utf-8");
            response.setStatus(HttpStatus.FORBIDDEN.value());
            writer= response.getWriter();
            Map<String,Object> map=new HashMap<>(16);
            map.put("result_code",HttpStatus.FORBIDDEN.value());
            map.put("result_reason","请登录!");
            writer.write(JsonUtils.serialize(map));
            writer.flush();
        } catch (IOException ex) {
            log.error("认证发送json数据IO错误",ex);
        }finally {
            if (writer != null) {
                writer.close();
            }
        }
    }
}
