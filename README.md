## 初始权限管理

### 权限管理概念

权限管理，一般指根据系统设置的安全规则或者安全策略，用户可以访问而且只能访问自己被授权的资源。权限管

理几乎出现在任何系统里面，前提是需要有用户和密码认证的系统。

>在权限管理的概念中，有两个非常重要的名词：
>
>认证：通过用户名和密码成功登陆系统后，让系统得到当前用户的角色身份。
>
>授权：系统根据当前用户的角色，给其授予对应可以操作的权限资源。

###  **完成权限管理需要三个对象**

用户：主要包含用户名，密码和当前用户的角色信息，可实现认证操作。

角色：主要包含角色名称，角色描述和当前角色拥有的权限信息，可实现授权操作。

权限：权限也可以称为菜单，主要包含当前权限名称，url地址等信息，可实现动态展示菜单。

>注：这三个对象中，用户与角色是多对多的关系，角色与权限是多对多的关系，用户与权限没有直接关系，二者是通过角色来建立关联关系的。





## 初识SpringSecurity

###  Spring Security概念

Spring Security是spring采用AOP思想，基于servlet过滤器实现的安全框架。它提供了完善的认证机制和方法级的

授权功能。是一款非常优秀的权限管理框架。



### Spring Security**简单入门**

> Spring Security博大精深，设计巧妙，功能繁杂，一言难尽，咱们还是直接上代码吧！



### 创建web工程并导入jar包

>Spring Security主要jar包功能介绍
>
>spring-security-core.jar
>
>核心包，任何Spring Security功能都需要此包。
>
>spring-security-web.jar
>
>web工程必备，包含过滤器和相关的Web安全基础结构代码。
>
>spring-security-confifig.jar
>
>用于解析xml配置文件，用到Spring Security的xml配置文件的就要用到此包。
>
>spring-security-taglibs.jar
>
>Spring Security提供的动态标签库，jsp

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>5.3.3.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-taglibs</artifactId>
    <version>5.3.3.RELEASE</version>
</dependency>
```





### 配置web.xml

```xml
<!--Spring Security过滤器链，注意过滤器名称必须叫springSecurityFilterChain--> 
<filter> 
    <filter-name>springSecurityFilterChain</filter-name> 
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class> 
</filter> 

<filter-mapping> 
    <filter-name>springSecurityFilterChain</filter-name> 
    <url-pattern>/*</url-pattern> 
</filter-mapping>
```





### 配置springSecurity的配置文件

![](https://img-blog.csdnimg.cn/2020060522132685.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xmlns:tx="http://www.springframework.org/schema/tx"
       xmlns:security="http://www.springframework.org/schema/security"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
			    http://www.springframework.org/schema/beans/spring-beans.xsd
			    http://www.springframework.org/schema/aop
			    http://www.springframework.org/schema/aop/spring-aop.xsd
			    http://www.springframework.org/schema/tx
			    http://www.springframework.org/schema/tx/spring-tx.xsd
                 http://www.springframework.org/schema/security
                http://www.springframework.org/schema/security/spring-security.xsd">

    <!--    配置springSecurity-->
    <!--
        auto-config='true' 表示自动加载springSecurity的配置文件
        use-expressions='true' 表示使用spring的el表达式来配置springSecurity
      -->

    <security:http auto-config="true" use-expressions="true">
        <!--拦截资源
            pattern='/**' 表示拦截所有资源
            access="hasAnyRole('ROLE-USER')"  表示只有ROLE-USER角色才能访问资源
         -->
        <security:intercept-url pattern="/**" access="hasAnyRole('ROLE-USER')"/>
    </security:http>

    <!--设置Spring Security认证用户信息的来源-->
    <!--
       springSecurity默认的认证必须是加密的，加上{noop}表示不加密认证
    -->
    <security:authentication-manager>
        <security:authentication-provider>
            <security:user-service>
                <security:user name="user" password="{noop}user" authorities="ROLE_USER" />
                <security:user name="admin" password="{noop}admin" authorities="ROLE_ADMIN" />
            </security:user-service>
        </security:authentication-provider>
    </security:authentication-manager>

</beans>
```



### 启动加载

让我们的springSecurity配置文件随着spring的加载而加载

```xml
<import resource="classpath:spring-security.xml"/>
```

![](https://img-blog.csdnimg.cn/20200605222252283.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





## Spring Security过滤器链

### Spring Security常用过滤器介绍

**过滤器是一种典型的** **AOP**思想，关于什么是过滤器，就不赘述了，谁还不知道凡是**web**工程都能用过滤器？

**接下来咱们就一起看看**Spring Security中这些过滤器都是干啥用的，源码我就不贴出来了，有名字，大家可以自

己在idea中Double Shift去。我也会在后续的学习过程中穿插详细解释。

1. org.springframework.security.web.context.SecurityContextPersistenceFilter

>  首当其冲的一个过滤器，作用之重要，自不必多言。
>
>  SecurityContextPersistenceFilter主要是使用SecurityContextRepository在session中保存或更新一个
>
>  SecurityContext，并将SecurityContext给以后的过滤器使用，来为后续fifilter建立所需的上下文。
>
>  SecurityContext中存储了当前用户的认证以及权限信息。

2. org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter

> 此过滤器用于集成SecurityContext到Spring异步执行机制中的WebAsyncManager

3. org.springframework.security.web.header.HeaderWriterFilter

> 向请求的Header中添加相应的信息,可在http标签内部使用security:headers来控制

4. org.springframework.security.web.csrf.CsrfFilter

> csrf又称跨域请求伪造，SpringSecurity会对所有post请求验证是否包含系统生成的csrf的token信息，
>
> 如果不包含，则报错。起到防止csrf攻击的效果。

5. org.springframework.security.web.authentication.logout.LogoutFilter北京市昌平区建材城西路金燕龙办公楼一层 电话：400-618-9090

> 匹配URL为/logout的请求，实现用户退出,清除认证信息。

6. org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

> 认证操作全靠这个过滤器，默认匹配URL为/login且必须为POST请求。

7. org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter

> 如果没有在配置文件中指定认证页面，则由该过滤器生成一个默认认证页面。

8. org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter

> 由此过滤器可以生产一个默认的退出登录页面

9. org.springframework.security.web.authentication.www.BasicAuthenticationFilter

> 此过滤器会自动解析HTTP请求中头部名字为Authentication，且以Basic开头的头信息。

10. org.springframework.security.web.savedrequest.RequestCacheAwareFilter

> 通过HttpSessionRequestCache内部维护了一个RequestCache，用于缓存HttpServletRequest

11. org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter

> 针对ServletRequest进行了一次包装，使得request具有更加丰富的API

12. org.springframework.security.web.authentication.AnonymousAuthenticationFilter

> 当SecurityContextHolder中认证信息为空,则会创建一个匿名用户存入到SecurityContextHolder中。
>
> spring security为了兼容未登录的访问，也走了一套认证流程，只不过是一个匿名的身份。

13. org.springframework.security.web.session.SessionManagementFilter

> SecurityContextRepository限制同一用户开启多个会话的数量

14. org.springframework.security.web.access.ExceptionTranslationFilter

> 异常转换过滤器位于整个springSecurityFilterChain的后方，用来转换整个链路中出现的异常

15. org.springframework.security.web.access.intercept.FilterSecurityInterceptor

> 获取所配置资源访问的授权信息，根据SecurityContextHolder中存储的用户信息来决定其是否有权限。

**好了！这一堆排山倒海的过滤器介绍完了。**

那么，是不是spring security一共就这么多过滤器呢？答案是否定的！随着spring-security.xml配置的添加，还

**会出现新的过滤器。**

那么，是不是spring security每次都会加载这些过滤器呢？答案也是否定的！随着spring-security.xml配置的修

改，有些过滤器可能会被去掉。



## 登录注销

### 自定义登录认证界面

```xml
<security:http auto-config="true" use-expressions="true">
    <!--让认证页面可以匿名访问-->
    <security:intercept-url pattern="/login.jsp" access="permitAll()"/>


    <!--拦截资源
            pattern='/**' 表示拦截所有资源
            access="hasAnyRole('ROLE-USER')"  表示只有ROLE-USER角色才能访问资源
         -->
    <security:intercept-url pattern="/**" access="hasAnyRole('ROLE_USER')"/>
    <!--配置认证信息 login-processing-url是登录的处理器url-->
    <security:form-login login-page="/login.jsp"
                         login-processing-url="/login"
                         default-target-url="/index.jsp"
                         authentication-failure-url="/failer.jsp"/>

    <!--配置退出登录信息-->
    <security:logout logout-url="/logout"
                     logout-success-url="/login.jsp"/>

    <!--去掉csrf过滤器(这里不去，因为jsp代码中携带了token信息)-->
    <security:csrf />
</security:http>
```





修改form表单的跳转路径

![](https://img-blog.csdnimg.cn/20200605235456912.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)







此时登入,报403

![](https://img-blog.csdnimg.cn/20200605235117336.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





### **SpringSecurity**的csrf防护机制

**CSRF**（Cross-site request forgery）跨站请求伪造，是一种难以防范的网络攻击方式。

自己的认证页面，请求方式为POST，但却没有携带token，所以才出现了403权限不足的异常。那么如何处理这个问题呢？

- 方式一：直接禁用csrf，不推荐。

- 方式二：在认证页面携带token请求

#### 方式一

```xml
<security:http auto-config="true" use-expressions="true">
    <!--让认证页面可以匿名访问-->
    <security:intercept-url pattern="/login.jsp" access="permitAll()"/>


    <!--拦截资源
            pattern='/**' 表示拦截所有资源
            access="hasAnyRole('ROLE-USER')"  表示只有ROLE-USER角色才能访问资源
         -->
    <security:intercept-url pattern="/**" access="hasAnyRole('ROLE_USER')"/>
    <!--配置认证信息 login-processing-url是登录的处理器url-->
    <security:form-login login-page="/login.jsp"
                         login-processing-url="/login"
                         default-target-url="/index.jsp"
                         authentication-failure-url="/failer.jsp"/>

    <!--配置退出登录信息-->
    <security:logout logout-url="/logout"
                     logout-success-url="/login.jsp"/>

    <!--去掉csrf过滤器-->
    <security:csrf disabled="true"/>
</security:http>
```





#### 方式二

在jsp页面中,引入

```jsp
<%@taglib uri="http://www.springframework.org/security/tags" prefix="security"%>
```



提交时携带token信息

![](https://img-blog.csdnimg.cn/20200605235055904.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





### 登出

在jsp页面中，引入

```jsp
<%@taglib uri="http://www.springframework.org/security/tags" prefix="security"%>
```



携带token信息

![](https://img-blog.csdnimg.cn/20200605235629634.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





### 初步实现认证

#### **让我们自己的UserService接口继承**UserDetailsService

```java
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
     * @param s 用户在浏览器输入的用户名
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        try {
            //根据用户名查询
            SysUser user = this.userDao.findByName(s);
            if(user==null){
                return null;
            }
            //查询该用户的所有权限
            List<SimpleGrantedAuthority> authorities=new ArrayList<>();
            List<SysRole> roles = user.getRoles();
            for (SysRole role : roles) {
                authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
            }
            //不使用加密要加{noop}
//            UserDetails userDetails=new User(user.getUsername(),"{noop}"+user.getPassword(),authorities);
            

            //使用加密
            UserDetails userDetails=new User(user.getUsername(),user.getPassword(),authorities);

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
    
    
}
```



#### 添加加密对象

```xml
<!--把加密对象放入到IOC容器中-->
<bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
```





#### 指定认证使用的业务对象和加密对象

```xml
<security:authentication-manager>
    <security:authentication-provider user-service-ref="userServiceImpl">
        <security:password-encoder ref="passwordEncoder"/>
    </security:authentication-provider>
</security:authentication-manager>
```





#### 注意

>加密使用的动态加盐加密，所有我们不需要自己去生成盐。而因为加了盐，每次生成的加密密码是不一样的

![](https://img-blog.csdnimg.cn/20200606010326393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)







## 设置用户状态

用户认证业务里，我们封装User对象时，选择了三个构造参数的构造方法，其实还有另一个构造方法：

![](https://img-blog.csdnimg.cn/20200607215320779.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)

可以看到，这个构造方法里多了四个布尔类型的构造参数，其实我们使用的三个构造参数的构造方法里这四个布尔

值默认都被赋值为了true，那么这四个布尔值到底是何意思呢？

- boolean enabled 是否可用

- boolean accountNonExpired 账户是否失效

- boolean credentialsNonExpired 密码是否失效

- boolean accountNonLocked 账户是否锁定



这四个参数必须同时为true认证才可以，为了节省时间，我只用第一个布尔值做个测试，修改认证业务代码：

```java
@Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        try {
            //根据用户名查询
            SysUser user = this.userDao.findByName(s);
            if(user==null){
                return null;
            }
            List<SimpleGrantedAuthority> authorities=new ArrayList<>();
            List<SysRole> roles = user.getRoles();
            for (SysRole role : roles) {
                authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
            }
            //不使用加密要加{noop}
//            UserDetails userDetails=new User(user.getUsername(),"{noop}"+user.getPassword(),authorities);

            //使用加密
            UserDetails userDetails=new User(user.getUsername(),user.getPassword(),user.getStatus()==1,true,true,true,authorities);

            return userDetails;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
```

此刻，只有用户状态为1的用户才能成功通过认证！





## 记住我

### 前台代码

![](https://img-blog.csdnimg.cn/20200607221124184.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



### 后台

```xml
<!--开启remenber me过滤器，设置token存储时间为60秒-->
<security:remember-me token-validity-seconds="60"/>
```

![](https://img-blog.csdnimg.cn/20200607222028630.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



### 结果

形成了一个token

![](https://img-blog.csdnimg.cn/20200607222112172.png)



### 安全性分析

记住我功能方便是大家看得见的，但是安全性却令人担忧。因为Cookie毕竟是保存在客户端的，很容易盗取，而且

cookie的值还与用户名、密码这些敏感数据相关，虽然加密了，但是将敏感信息存在客户端，还是不太安全。那么

这就要提醒喜欢使用此功能的，用完网站要及时手动退出登录，清空认证信息。

此外，SpringSecurity还提供了remember me的另一种相对更安全的实现机制 :在客户端的cookie中，仅保存一个

无意义的加密串（与用户名、密码等敏感数据无关），然后在db中保存该加密串-用户信息的对应关系，自动登录

时，用cookie中的加密串，到db中验证，如果通过，自动登录才算通过。





### 持久化**remember me**信息

创建一张表，注意这张表的名称和字段都是固定的，不要修改。

```sql
CREATE TABLE `persistent_logins` ( 
    `username` varchar(64) NOT NULL, 
    `series` varchar(64) NOT NULL, 
    `token` varchar(64) NOT NULL, 
    `last_used` timestamp NOT NULL, PRIMARY KEY (`series`) 
) ENGINE=InnoDB DEFAULT CHARSET=utf8
```



然后将spring-security.xml中 改为：

```xml
<!--
 开启remember me过滤器，
 data-source-ref="dataSource" 指定数据库连接池
 token-validity-seconds="60" 设置token存储时间为60秒 可省略 
 remember-me-parameter="remember-me" 指定记住的参数名 可省略 --> 
<security:remember-me data-source-ref="dataSource" token-validity-seconds="60" remember-me-parameter="remember-me"/>
```



### 持久化结果

![](https://img-blog.csdnimg.cn/20200607223015193.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)







```xml
<!--开启权限控制的注解支持
        secured-annotations  springSecurity内部的权限注解控制开关
        pre-post-annotations spring指定的权限控制的开关
        jsr250-annotations  开启java250注解支持 
    -->
<security:global-method-security secured-annotations="enabled" pre-post-annotations="enabled" jsr250-annotations="enabled"/>
```





## 授权注解

### 开启注解

```xml
<!--开启权限控制的注解支持
        secured-annotations  springSecurity内部的权限注解控制开关
        pre-post-annotations spring指定的权限控制的开关
        jsr250-annotations  开启java250注解支持
    -->
<security:global-method-security secured-annotations="enabled" pre-post-annotations="enabled" jsr250-annotations="enabled"/>
```





注意的是，记得在我们的http上这两个配置

![](https://img-blog.csdnimg.cn/20200608003327597.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





### 使用

三种不同风格的注解

```java
@Secured({"ROLE_PRODUCT","ROLE_ADMIN"})  //springSecurity内部指定的注解
@RolesAllowed("ROLE_PRODUCT,ROLE_ADMIN")  //jsr250注解
@PreAuthorize("hasAnyRole('ROLE_PRODUCT','ROLE_ADMIN')")  //spring的el表达式
@RequestMapping("/findAll")
public String findAll(){
    return "product-list";
}
```





## 相关配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xmlns:tx="http://www.springframework.org/schema/tx"
       xmlns:security="http://www.springframework.org/schema/security"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/aop
                           http://www.springframework.org/schema/aop/spring-aop.xsd
                           http://www.springframework.org/schema/tx
                           http://www.springframework.org/schema/tx/spring-tx.xsd
                           http://www.springframework.org/schema/security
                           http://www.springframework.org/schema/security/spring-security.xsd">

    <!--释放进行资源-->
    <security:http pattern="/css/**" security="none"/>
    <security:http pattern="/img/**" security="none"/>
    <security:http pattern="/plugins/**" security="none"/>
    <security:http pattern="/failer.jsp" security="none"/>


    <!--    配置springSecurity-->
    <!--
        auto-config='true' 表示自动加载springSecurity的配置文件
        use-expressions='true' 表示使用spring的el表达式来配置springSecurity
      -->

    <security:http auto-config="true" use-expressions="true">
        <!--让认证页面可以匿名访问-->
        <security:intercept-url pattern="/login.jsp" access="permitAll()"/>


        <!--拦截资源
            pattern='/**' 表示拦截所有资源
            access="hasAnyRole('ROLE-USER')"  表示只有ROLE-USER角色才能访问资源
         -->
        <security:intercept-url pattern="/**" access="hasAnyRole('ROLE_USER')"/>
        <!--配置认证信息 login-processing-url是登录的处理器url-->
        <security:form-login login-page="/login.jsp"
                             login-processing-url="/login"
                             default-target-url="/index.jsp"
                             authentication-failure-url="/failer.jsp"/>

        <!--配置退出登录信息-->
        <security:logout logout-url="/logout"
                         logout-success-url="/login.jsp"/>

        <!--去掉csrf过滤器-->
        <security:csrf disabled="true"/>


        <!--
        开启remember me过滤器，
         data-source-ref="dataSource" 指定数据库连接池
         token-validity-seconds="60" 设置token存储时间为60秒 可省略
         remember-me-parameter="remember-me" 指定记住的参数名 可省略 -->
        <security:remember-me data-source-ref="dataSource" token-validity-seconds="60"
                              remember-me-parameter="remember-me"/>

        <!--只能处理403异常-->
        <security:access-denied-handler error-page="/403.jsp"/>
    </security:http>

    <!--把加密对象放入到IOC容器中-->
    <bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>


    <!--设置Spring Security认证用户信息的来源-->
    <!--
       springSecurity默认的认证必须是加密的，加上{noop}表示不加密认证
    -->
    <security:authentication-manager>
        <security:authentication-provider user-service-ref="userServiceImpl">
            <!--    <security:user-service>-->
            <!--        <security:user name="user" password="{noop}user" authorities="ROLE_USER" />-->
            <!--        <security:user name="admin" password="{noop}admin" authorities="ROLE_ADMIN" />-->
            <!--    </security:user-service>-->
            <security:password-encoder ref="passwordEncoder"/>
        </security:authentication-provider>

    </security:authentication-manager>

    <!--开启权限控制的注解支持
        secured-annotations  springSecurity内部的权限注解控制开关
        pre-post-annotations spring指定的权限控制的开关
        jsr250-annotations  开启java250注解支持
    -->
    <security:global-method-security secured-annotations="enabled" pre-post-annotations="enabled"
                                     jsr250-annotations="enabled"/>

</beans>
```







## springboot整合

### 引入依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```



### 测试

随便写一个接口，访问

![](https://img-blog.csdnimg.cn/20200608105047137.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



用户名是user，密码是随机生成的

![](https://img-blog.csdnimg.cn/20200608105135977.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





### 配置springsecurity

```java
package top.codekiller.test.springsecurity_springboot.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author codekiller
 * @date 2020/6/8 11:00
 * @description DES
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true,jsr250Enabled = true,prePostEnabled = true) //开启三种方式的注解
public class springSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private IUserService userService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 验证用户的来源[内存，数据库]
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //内存指定
      //  auth.inMemoryAuthentication()
      //      .withUser("user")
      //      .password("{noop}123")
      //      .roles("USER","ADMIN");    //不要加前缀，ROLE_USER=>USER

        //数据库指定
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }


    //配置springSecurity相关信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //释放静态资源,指定资源拦截规则，指定自定义认证页面，指定退出认证配置，csrf
        http.authorizeRequests()
            .antMatchers("/login.jsp","/failer.jsp","/css/**","/img/**","/plugin/**").permitAll()
            .antMatchers("/**").hasAnyRole("USER","ADMIN")
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
            .loginPage("/login.jsp")
            .loginProcessingUrl("/login")
            .defaultSuccessUrl("/index.jsp")
            .failureForwardUrl("/failer.jsp")
            .permitAll()
            .and()
            .logout()
            .logoutUrl("/logout")
            .logoutSuccessUrl("/login.jsp")
            .invalidateHttpSession(true)
            .permitAll()
            .and()
            .csrf()
            .disable();
    }
}
```



### 实体类

#### SysUser

```java
package top.codekiller.test.springsecurity_springboot.pojo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
public class SysUser implements UserDetails {
    private Integer id;
    private String username;
    private String password;
    private Integer status;
    private List<SysRole> roles;


    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```





#### SysRole

```java
package top.codekiller.test.springsecurity_springboot.pojo;

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
```



### mapper接口

#### UserMapper

```java
package top.codekiller.test.springsecurity_springboot.mapper;
import tk.mybatis.mapper.common.Mapper;
import org.apache.ibatis.annotations.*;
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
```





#### RoleMapper

```java
package top.codekiller.test.springsecurity_springboot.mapper;
import tk.mybatis.mapper.common.Mapper;
import org.apache.ibatis.annotations.Select;
import top.codekiller.test.springsecurity_springboot.pojo.SysRole;

import java.util.List;

/**
 * @author codekiller
 * @date 2020/6/8 14:40
 * @description DES
 */
public interface RoleMapper extends Mapper<SysRole>{

    @Select("select r.id,r.role,r.role_name roleName,r.role_desc roleDesc from sys_role r,sys_user_role ur where r.id=ur.rid and ur.uid=#{uid} ")
    List<SysRole> findByUid(Integer uid);
}
```





### service

```java
/**
 * @author codekiller
 * @date 2020/6/8 15:00
 * @description DES
 */
public interface IUserService extends UserDetailsService {
}
```



```java
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
```



### controller

```java
package top.codekiller.test.springsecurity_springboot.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author codekiller
 * @date 2020/6/8 10:41
 * @description DES
 */
@Controller
@RequestMapping("/product")
public class ProductController {

    @Secured("ROLE_PRODUCT")  //控制权限访问
    @RequestMapping("/findAll")
    @ResponseBody
    public String findAll(){
        return "product-list";
    }
}
```

​	





## springboot结合JWT的使用

### JWT基本概念

**JWT**生成的token由三部分组成：

- 头部：主要设置一些规范信息，签名部分的编码格式就在头部中声明。

- 载荷：token中存放有效信息的部分，比如用户名，用户角色，过期时间等，但是不要放密码，会泄露！

- 签名：将头部与载荷分别采用base64编码后，用“.”相连，再加入盐，最后使用头部声明的编码类型进行编码，就得到了签名。



### Rsa基本概念

基本原理：同时生成两把密钥：私钥和公钥，私钥隐秘保存，公钥可以下发给信任客户端

- 私钥加密，持有私钥或公钥才可以解密

- 公钥加密，持有私钥才可解密

优点：安全，难以破解

缺点：算法比较耗时，为了安全，可以接受

历史：三位数学家Rivest、Shamir 和 Adleman 设计了一种算法，可以实现非对称加密。这种算法用他们三

个人的名字缩写：RSA。



### 认证服务

#### 引入依赖

列出主要安全依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.0</version>
</dependency>

<dependency>
    <groupId>joda-time</groupId>
    <artifactId>joda-time</artifactId>
    <version>2.10.5</version>
</dependency>
```



#### 配置application.yml

```yaml
manager:
  jwt:
    secret: ea61b46dse2@manager@9ds966@codekiller@33da # 登录校验的密钥
    pubKeyPath: E:\chrome\token\\rsa.pub # 公钥地址
    priKeyPath: E:\chrome\token\\rsa.pri # 私钥地址
    expire: 30 # 过期时间,单位分钟
    headerName: Authorization  #token的名称
```



#### 配置properties

```java
package top.codekiller.test.springsecurity.properties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import top.codekiller.test.springsecurity.utils.RsaUtils;
import javax.annotation.PostConstruct;
import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * @author codekiller
 * @date 2020/5/22 13:30
 *
 * 公钥和私钥的配置类
 */
@ConfigurationProperties(prefix = "manager.jwt")
@Slf4j
@Data
public class JwtProperties {


    /**
     * 密钥
     */
    private String secret;

    /**
     * 公钥保存路径
     */
    private String pubKeyPath;


    /**
     * 私钥保存路径
     */
    private String priKeyPath;


    /**
     * token过期时间
     */
    private int expire;

    /**
     * 公钥
     */
    private PublicKey publicKey;


    /**
     * 私钥
     */
    private PrivateKey privateKey;

    /**
     * token名称
     */
    private String headerName;

    /**
     * @PostContruct：在构造方法执行之后执行该方法
     * 创建私钥和公钥，并且获取赋值
     */
    @PostConstruct
    public void init(){
        try {
            File pubKey = new File(pubKeyPath);
            File priKey = new File(priKeyPath);
            if (!pubKey.exists() || !priKey.exists()) {
                // 生成公钥和私钥
                RsaUtils.generateKey(pubKeyPath, priKeyPath, secret);
            }
            // 获取公钥和私钥
            this.publicKey = RsaUtils.getPublicKey(pubKeyPath);
            this.privateKey = RsaUtils.getPrivateKey(priKeyPath);
        } catch (Exception e) {
            log.error("初始化公钥和私钥失败！", e);
            throw new RuntimeException();
        }
        }
}
```







#### <span id="pojo">实体类</span>

##### SysUser (UserDetails)

```java
@Data
public class SysUser implements UserDetails {
    private Integer id;
    private String username;
    private String password;
    private Integer status;
    private List<SysRole> roles;

    /**
     * 权限集合
     * @return
     */
    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    /**
     * 账号失效
     * @return
     */
    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 账号锁定
     * @return
     */
    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 密码失效
     * @return
     */
    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 是否可用
     * @return
     */
    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }
}

```



##### SysRole(GrantedAuthority)

```java
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
```



#### mapper

##### RoleMapper

```java
public interface RoleMapper {

    @Select("select r.id,r.role_name,r.role_desc from sys_role r,sys_user_role ur where r.id=ur.rid and ur.uid=#{uid} ")
    List<SysRole> findByUid(Integer uid);
}
```



##### UserMapper

```java
public interface UserMapper  {

    @Select("select * from sys_user where username=#{name}")
    @Results({
        @Result(id=true,property = "id",column = "id"),
        @Result(property = "roles",column = "id",javaType = List.class,
                many = @Many(select = "top.codekiller.test.springsecurity.mapper.RoleMapper.findByUid"))
    })
    SysUser findByName(String name);

}
```





#### UserService

登录的验证

```java
public interface IUserService extends UserDetailsService {
}
```



```java
@Service
@Transactional(rollbackFor = Exception.class)
public class UserServiceImpl implements IUserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return this.userMapper.findByName(s);
    }
}
```





#### WebSecurityConfig

security的配置类

```java
@EnableConfigurationProperties(JwtProperties.class)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true) //开启注解
public class  WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private IUserService userService;


    @Autowired
    private JwtProperties jwtProperties;



    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 验证用户的来源[内存，数据库]
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //数据库指定
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }


    /**
     * 配置springSecurity相关信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //释放静态资源,指定资源拦截规则，指定自定义认证页面，指定退出认证配置，csrf
        http.cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/**").hasAnyRole("USER","ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .logout()
                .logoutUrl("/logout")
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .addFilter(new JwtAccreditFilter(super.authenticationManager(),this.jwtProperties))
                .addFilter(new JwtVerifyFilter(super.authenticationManager(),this.jwtProperties))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }
}
```





#### 编写过滤器

##### JwtAccreditFilter

```java
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
```





##### JwtVerifyFilter

```java
/**
 * @author codekiller
 * @date 2020/6/8 20:18
 * @description 认证过滤器
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
```





### 资源服务

#### 实体类

和认证服务的一样，User和Role连个必要实体类

[点击](#pojo)



#### WebSecurityConfig

```java
@EnableConfigurationProperties(JwtProperties.class)
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true) //开启注解
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtProperties jwtProperties;

    /**
     * 配置springSecurity相关信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //指定资源拦截规则,指定退出认证配置，csrf
        http.cors().and().csrf().disable()
            .authorizeRequests()
            .antMatchers("/product").hasAnyRole("ADMIN")
            .anyRequest()
            .authenticated()
            .and()
            .addFilter(new JwtVerifyFilter(super.authenticationManager(),this.jwtProperties))
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }
}
```





#### 配置application.yml

```java
manager:
  jwt:
    pubKeyPath: E:\chrome\token\\rsa.pub # 公钥地址
    headerName: Authorization
```



#### 配置properties

```java
/**
 * @author codekiller
 * @date 2020/5/27 0:30
 * @description token配置类
 */
@ConfigurationProperties(prefix = "manager.jwt")
@Slf4j
@Data
public class JwtProperties {


    /**
     * 公钥
     */
    private PublicKey publicKey;

    /**
     * 公钥地址
     */
    private String pubKeyPath;


    /**
     * token的请求头名称
     */
    private String headerName;


    @PostConstruct
    public void init(){
        try {
            // 获取私钥
            this.publicKey = RsaUtils.getPublicKey(pubKeyPath);
        } catch (Exception e) {
            log.error("初始化公钥失败！", e);
            throw new RuntimeException();
        }
    }
}
```







#### 认证过滤器(JwtVerifyFilter)

```java
/**
 * @author codekiller
 * @date 2020/6/8 20:18
 * @description 认证过滤器
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
        String header=request.getHeader(this.jwtProperties.getHeaderName());

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
```







### 结果

写一个接口进行测试

```java
@RestController
@RequestMapping("/product")
public class ProductController {

    @Secured({"ROLE_ADMIN"})  //控制权限访问
    @RequestMapping("/findAll")
    public String findAll(){
        return "product-list";
    }
}
```





进行登录，获取token

![](https://img-blog.csdnimg.cn/20200609002801164.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





访问资源服务

![](https://img-blog.csdnimg.cn/20200609002843856.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





## OAuth2

### **概念说明**

先说OAuth，OAuth是Open Authorization的简写。

OAuth协议为用户资源的授权提供了一个安全的、开放而又简易的标准。与以往的授权方式不同之处是

OAuth的授权不会使第三方触及到用户的帐号信息（如用户名与密码），即第三方无需使用用户的用户名与

密码就可以申请获得该用户资源的授权，因此OAuth是安全的。

OAuth2.0是OAuth协议的延续版本，但不向前兼容(即完全废止了OAuth1.0)。

### **使用场景**

假设，A网站是一个打印照片的网站，B网站是一个存储照片的网站，二者原本毫无关联。

如果一个用户想使用A网站打印自己存储在B网站的照片，那么A网站就需要使用B网站的照片资源才行。

按照传统的思考模式，我们需要A网站具有登录B网站的用户名和密码才行，但是，现在有了OAuth2，只需要A网

站获取到使用B网站照片资源的一个通行令牌即可！这个令牌无需具备操作B网站所有资源的权限，也无需永久有

效，只要满足A网站打印照片需求即可。

这么听来，是不是有点像单点登录？NONONO！千万不要混淆概念！单点登录是用户一次登录，自己可以操作其

他关联的服务资源。OAuth2则是用户给一个系统授权，可以直接操作其他系统资源的一种方式。

但SpringSecurity的OAuth2也是可以实现单点登录的！

总结一句：SpringSecurity的OAuth2可以做服务之间资源共享，也可以实现单点登录！



### **OAuth2.0**中四种授权方式

#### **授权码模式（**authorization code）

**流程**

1. 用户访问客户端，客户端通过用户代理向认证服务器请求授权码；(授权码只能使用一次)
2. 用户同意授权；
3. 认证服务器通过用户代理返回授权码给客户端；
4. 客户端携带授权码向认证服务器请求访问令牌（AccessToken）；
5. 认证服务器返回访问令牌；
6. 客户端携带访问令牌向资源服务器请求资源；
7. 资源服务器返回资源。

![](https://img-blog.csdnimg.cn/20200609215636486.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



使用场景

授权码模式是OAuth2中最安全最完善的一种模式，应用场景最广泛，可以实现服务之间的调用，常见的微

信，QQ等第三方登录也可采用这种方式实现。







#### 简化模式（implicit）

**流程**

说明：简化模式中没有【A服务认证服务】这一部分，全部有【A服务客户端】与B服务交互，整个过程不再有

授权码，token直接暴露在浏览器。

1. 用户访问客户端，客户端通过用户代理向认证服务器请求授权码；
2. 用户同意授权；
3. 认证服务器返回一个重定向地址，该地址的url的Hash部分包含了令牌；
4. 用户代理向资源服务器发送请求，其中不带令牌信息；
5. 资源服务器返回一个网页，其中包含的脚本可以获取Hash中的令牌；
6. 用户代理执行脚本提取令牌；
7. 用户代理将令牌返回给客户端；
8. 客户端携带令牌向资源服务器请求资源；
9. 资源服务器返回资源。
   

![](https://img-blog.csdnimg.cn/20200609215818920.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



使用场景

适用于A服务没有服务器的情况。比如：纯手机小程序，JavaScript语言实现的网页插件等。





####  密码模式（resource owner password credentials）

**流程**

1. 用户向客户端提供用户名密码；
2. 客户端将用户名和密码发给认证服务器请求令牌；
3. 认证服务器确认无误后，向客户端提供访问令牌；
4. 客户端携带令牌向资源服务器请求访问资源；
5. 资源服务器返回资源。

![](https://img-blog.csdnimg.cn/20200609220123881.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



**使用场景**

此种模式虽然简单，但是用户将B服务的用户名和密码暴露给了A服务，需要两个服务信任度非常高才能使

用。





#### **客户端模式（**client credentials）

**流程**

说明：这种模式其实已经不太属于OAuth2的范畴了。A服务完全脱离用户，以自己的身份去向B服务索取

token。换言之，用户无需具备B服务的使用权也可以。完全是A服务与B服务内部的交互，与用户无关了。

1. 客户端向认证服务器进行身份认证，并要求一个访问令牌；
2. 认证服务器确认无误后，向客户端提供访问令牌；
3. 客户端携带令牌向资源服务器请求访问资源；
4. 资源服务器返回资源。

![](https://img-blog.csdnimg.cn/20200609220305294.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



**使用场景**

A服务本身需要B服务资源，与用户无关。





### 建表

官网地址

[官网](https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/resources/schema.sql)



核心表：**oauth_client_details**

| 字段名                  | 字段说明                                                     |
| :---------------------- | :----------------------------------------------------------- |
| client_id               | 主键,必须唯一,不能为空. 用于唯一标识每一个客户端(client); 在注册时必须填写(也可由服务 端自动生成). 对于不同的grant_type,该字段都是必须的. 在实际应用中的另一个名称叫appKey,与client_id是同一个概念. |
| resource_ids            | 客户端所能访问的资源id集合,多个资源时用逗号(,)分隔,如: "unity-resource,mobile-resource".  该字段的值必须来源于与`security.xml`中标签`‹oauth2:resource-server`的属性`resource-id`值一致. 在`security.xml`配置有几个`‹oauth2:resource-server`标签, 则该字段可以使用几个该值.  在实际应用中, 我们一般将资源进行分类,并分别配置对应的`‹oauth2:resource-server`,如订单资源配置一个`‹oauth2:resource-server`, 用户资源又配置一个`‹oauth2:resource-server`. 当注册客户端时,根据实际需要可选择资源id,也可根据不同的注册流程,赋予对应的资源id. |
| client_secret           | appKey,与client_id是同一个概念. 用于指定客户端(client)的访问密匙; 在注册时必须填写(也可由服务端自动生成).  对于不同的grant_type,该字段都是必须的. 在实际应用中的另一个名称叫appSecret,与client_secret是同一个概念. |
| scope                   | 指定客户端申请的权限范围,可选值包括*read*,*write*,*trust*;若有多个权限范围用逗号(,)分隔,如: "read,write".  scope的值与`security.xml`中配置的`‹intercept-url`的`access`属性有关系. 如`‹intercept-url`的配置为 `‹intercept-url pattern="/m/**" access="ROLE_MOBILE,SCOPE_READ"/>` 则说明访问该URL时的客户端必须有*read*权限范围. *write*的配置值为*SCOPE_WRITE*, *trust*的配置值为*SCOPE_TRUST*.  在实际应该中, 该值一般由服务端指定, 常用的值为*read,write*. |
| authorized_grant_types  | 指定客户端支持的grant_type,可选值包括*authorization_code*,*password*,*refresh_token*,*implicit*,*client_credentials*, 若支持多个grant_type用逗号(,)分隔,如: "authorization_code,password".  在实际应用中,当注册时,该字段是一般由服务器端指定的,而不是由申请者去选择的,最常用的grant_type组合有:  "authorization_code,refresh_token"(针对通过浏览器访问的客户端);  "password,refresh_token"(针对移动设备的客户端).  *implicit*与*client_credentials*在实际中很少使用. |
| web_server_redirect_uri | 客户端的重定向URI,可为空, 当grant_type为`authorization_code`或`implicit`时, 在Oauth的流程中会使用并检查与注册时填写的redirect_uri是否一致. 下面分别说明:           当grant_type=`authorization_code`时, 第一步 `从 spring-oauth-server获取 "code"`时客户端发起请求时必须有`redirect_uri`参数, 该参数的值必须与 `web_server_redirect_uri`的值一致. 第二步 `用 "code" 换取 "access_token"` 时客户也必须传递相同的`redirect_uri`.  在实际应用中, *web_server_redirect_uri*在注册时是必须填写的, 一般用来处理服务器返回的`code`, 验证`state`是否合法与通过`code`去换取`access_token`值.  在[spring-oauth-client](http://git.oschina.net/mkk/spring-oauth-client)项目中, 可具体参考`AuthorizationCodeController.java`中的`authorizationCodeCallback`方法.      当grant_type=`implicit`时通过`redirect_uri`的hash值来传递`access_token`值.如: `http://localhost:7777/spring-oauth-client/implicit#access_token=dc891f4a-ac88-4ba6-8224-a2497e013865&token_type=bearer&expires_in=43199` 然后客户端通过JS等从hash值中取到`access_token`值. |
| authorities             | 指定客户端所拥有的Spring Security的权限值,可选, 若有多个权限值,用逗号(,)分隔, 如: "ROLE_UNITY,ROLE_USER".  对于是否要设置该字段的值,要根据不同的grant_type来判断, 若客户端在Oauth流程中需要用户的用户名(username)与密码(password)的(`authorization_code`,`password`),  则该字段可以不需要设置值,因为服务端将根据用户在服务端所拥有的权限来判断是否有权限访问对应的API.  但如果客户端在Oauth流程中不需要用户信息的(`implicit`,`client_credentials`),  则该字段必须要设置对应的权限值, 因为服务端将根据该字段值的权限来判断是否有权限访问对应的API. (请在[spring-oauth-client](http://git.oschina.net/mkk/spring-oauth-client)项目中来测试不同grant_type时authorities的变化) |
| access_token_validity   | 设定客户端的access_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 12, 12小时).  在服务端获取的access_token JSON数据中的`expires_in`字段的值即为当前access_token的有效时间值.  在项目中, 可具体参考`DefaultTokenServices.java`中属性`accessTokenValiditySeconds`.  在实际应用中, 该值一般是由服务端处理的, 不需要客户端自定义. |
| refresh_token_validity  | 设定客户端的refresh_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 24 * 30, 30天).  若客户端的grant_type不包括`refresh_token`,则不用关心该字段 在项目中, 可具体参考`DefaultTokenServices.java`中属性`refreshTokenValiditySeconds`.    在实际应用中, 该值一般是由服务端处理的, 不需要客户端自定义. |
| additional_information  | 这是一个预留的字段,在Oauth的流程中没有实际的使用,可选,但若设置值,必须是JSON格式的数据,如: `{"country":"CN","country_code":"086"}` 按照`spring-security-oauth`项目中对该字段的描述  *Additional information for this client, not need by the vanilla OAuth protocol but might be useful, for example,for storing descriptive information.*  (详见`ClientDetails.java`的`getAdditionalInformation()`方法的注释)在实际应用中, 可以用该字段来存储关于客户端的一些其他信息,如客户端的国家,地区,注册时的IP地址等等. |
| create_time             | 数据的创建时间,精确到秒,由数据库在插入数据时取当前系统时间自动生成(扩展字段) |
| archived                | 用于标识客户端是否已存档(即实现逻辑删除),默认值为"0"(即未存档).  对该字段的具体使用请参考`CustomJdbcClientDetailsService.java`,在该类中,扩展了在查询client_details的SQL加上*archived = 0*条件 (扩展字段) |
| trusted                 | 设置客户端是否为受信任的,默认为"0"(即不受信任的,1为受信任的).  该字段只适用于grant_type="authorization_code"的情况,当用户登录成功后,若该值为0,则会跳转到让用户Approve的页面让用户同意授权,  若该字段为1,则在登录后不需要再让用户Approve同意授权(因为是受信任的).  对该字段的具体使用请参考`OauthUserApprovalHandler.java`. (扩展字段) |
| autoapprove             | 设置用户是否自动Approval操作, 默认值为 "false", 可选值包括 "true","false", "read","write".  该字段只适用于grant_type="authorization_code"的情况,当用户登录成功后,若该值为"true"或支持的scope值,则会跳过用户Approve的页面, 直接授权.  该字段与 trusted 有类似的功能, 是 spring-security-oauth2 的 2.0 版本后添加的新属性. |





### 导包

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>
```





### 授权中心的安全配置

#### 配置文件

```yaml
server:
  port: 8082
spring:
  datasource:
    username: root
    password: root
    url: jdbc:mysql://localhost:3306/spring_security?characterEncoding=UTF-8&serverTimezone=UTC
    driver-class-name: com.mysql.jdbc.Driver
  main:
    allow-bean-definition-overriding: true



mybatis:
  type-aliases-package: top.codekiller.security.pojo
  configuration:
    map-underscore-to-camel-case: true
logging:
  level:
    top.codekiller.security: debug
```



#### 实体类

```java
@Data
public class SysUser implements UserDetails {
    private Integer id;
    private String username;
    private String password;
    private Integer status;
    private List<SysRole> roles;


    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```



```java
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
```



#### service

```java
public interface IUserService extends UserDetailsService {
}

@Service
@Transactional(rollbackFor = Exception.class)
public class UserServiceImpl implements IUserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return this.userMapper.findByName(s);
    }
}
```



#### mapper

```java
public interface UserMapper  {

    @Select("select * from sys_user where username=#{name}")
    @Results({
        @Result(id=true,property = "id",column = "id"),
        @Result(property = "roles",column = "id",javaType = List.class,
                many = @Many(select = "top.codekiller.security.mapper.RoleMapper.findByUid"))
    })
    SysUser findByName(String name);

}

public interface RoleMapper {

    @Select("select r.id,r.role_name,r.role_desc from sys_role r,sys_user_role ur where r.id=ur.rid and ur.uid=#{uid} ")
    List<SysRole> findByUid(Integer uid);
}
```



#### security配置类

```java
package top.codekiller.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import top.codekiller.security.service.IUserService;

/**
 * @author codekiller
 * @date 2020/6/9 18:06
 * @description 授权中心security配置类
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private IUserService userService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 验证用户的来源[内存，数据库]
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }

    /**
     * 配置springSecurity相关信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .loginProcessingUrl("/login")
            .permitAll()
            .and()
            .csrf()
            .disable();
    }


    /**
     * AuthenticationManager对象在OAuth2认证服务中使用，放入到IOC容器中
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```



#### oauth配置类

```java
package top.codekiller.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import top.codekiller.security.service.IUserService;

import javax.sql.DataSource;

/**
 * @author codekiller
 * @date 2020/6/9 18:27
 * @description 授权中心oauth配置类
 */
@Configuration
@EnableAuthorizationServer
public class OAuthServerConfig extends AuthorizationServerConfigurerAdapter {



    /**
     * 数据库连接池对象
     */
    @Autowired
    private DataSource dataSource;


    /**
     * 认证业务对象
     */
    @Autowired
    private IUserService userService;

    /**
     *授权模式专用对象
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 客户端信息来源
     * @return
     */
    @Bean
    public JdbcClientDetailsService jdbcClientDetailsService(){
        return new JdbcClientDetailsService(dataSource);
    }


    /**
     * token保存策略
     * @return
     */
    @Bean
    public TokenStore tokenStore(){
        return new JdbcTokenStore(dataSource);
    }

    /**
     * 授权信息保存策略
     * @return
     */
    @Bean
    public ApprovalStore approvalStore(){
        return new JdbcApprovalStore(dataSource);
    }

    /**
     * 授权码模式专用数据来源
     * @return
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(){
        return new JdbcAuthorizationCodeServices(dataSource);
    }






    /**
     * 指定客户端信息的数据库来源
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(jdbcClientDetailsService());
    }

    /**
     * 检测token的策略
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.allowFormAuthenticationForClients();
        security.checkTokenAccess("isAuthenticated()");
    }

    /**
     * OAuth2的主配置信息
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
            .approvalStore(approvalStore())
            .authorizationCodeServices(authorizationCodeServices())
            .tokenStore(tokenStore())
            .userDetailsService(userService);

    }
}
```







### 资源服务的安全配置

#### 配置文件

```yaml
server:
  port: 8081
spring:
  datasource:
    username: root
    password: root
    url: jdbc:mysql://localhost:3306/spring_security?characterEncoding=UTF-8&serverTimezone=UTC
    driver-class-name: com.mysql.jdbc.Driver
  main:
    allow-bean-definition-overriding: true

logging:
  level:
    top.codekiller.security: debug
```





#### 配置类

tokenstore的常用策略

![](https://img-blog.csdnimg.cn/20200609173740646.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



```java
package top.codekiller.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

/**
 * @author codekiller
 * @date 2020/6/9 17:19
 * @description 资源服务的安全配置
 */
@Configuration
@EnableResourceServer
public class OAuthConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    /**
     * 指定token的持久化策略(TokenStore有五种策略这里使用jdbc策略)
     * @return
     */
    public TokenStore jdbcTokenStore(){
        return new JdbcTokenStore(dataSource);
    }

    /**
     * 指定当前资源的id和存储方案
     * @param resources
     * @throws Exception
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("product_api").tokenStore(jdbcTokenStore());
    }


    /**
     *相关请求http配置
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            //指定不同请求方式访问资源所需要的权限，一般查询是read，其余是write。
            .antMatchers(HttpMethod.GET, "/**")
            .access("#oauth2.hasScope('read')")
            .antMatchers(HttpMethod.POST, "/**").access("#oauth2.hasScope('write')")
            .antMatchers(HttpMethod.PATCH, "/**").access("#oauth2.hasScope('write')")
            .antMatchers(HttpMethod.PUT, "/**").access("#oauth2.hasScope('write')")
            .antMatchers(HttpMethod.DELETE, "/**").access("#oauth2.hasScope('write')")
            .and()
            .headers().addHeaderWriter((request, response) -> {
            response.addHeader("Access-Control-Allow-Origin", "*");//允许跨域
            if (request.getMethod().equals("OPTIONS")) {//如果是跨域的预检请求，则原封不动向下传达请 求头信息
                response.setHeader("Access-Control-Allow-Methods", request.getHeader("Access- Control-Request-Method"));
                response.setHeader("Access-Control-Allow-Headers", request.getHeader("Access- Control-Request-Headers"));
            }
        });
    }

}
```





#### 测试接口

```java
@RestController
@RequestMapping("/product")
public class ProductController {

    @Secured("ROLE_ADMIN")
    @GetMapping("/findAll")
    public String findAll(){
        return "参评列表查询成功";
    }
}
```





### 授权码模式测试

访问http://localhost:8082/oauth/authorize?response_type=code&client_id=test_one



跳转到登录处理界面

![](https://img-blog.csdnimg.cn/20200609192124690.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



因为我们在配置中配置了login地址

![](https://img-blog.csdnimg.cn/20200609192200335.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



填写账号密码成功后选择权限

![](https://img-blog.csdnimg.cn/2020060921372570.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



获取授权码

![](https://img-blog.csdnimg.cn/20200609200504675.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)

跳转地址是在数据库记录的地址

![](https://img-blog.csdnimg.cn/20200609200545264.png)



获取token

- grant_type是授权码模式,共五种选项
  - client_credentials 客户端模式   
  - implicit  简单模式
  - authorization_code  授权码模式
  - refresh_token 刷新token
  - password 密码模式

![](https://img-blog.csdnimg.cn/20200609191459601.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



携带token进行访问资源

![](https://img-blog.csdnimg.cn/2020060919170358.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





>注意：授权码只能使用一次

![](https://img-blog.csdnimg.cn/20200609210458800.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



### 简单模式

不建议使用，token直接出现在地址栏，不安全！

![](https://sorry.xuty.tk/nick/example.png)



访问 http://localhost:8082/oauth/authorize?response_type=token&client_id=test_one

![](https://img-blog.csdnimg.cn/20200609201153830.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



![](https://img-blog.csdnimg.cn/20200609201438869.png)





>可以看到，我们获取的token是一样的，因为当前用户的token没有过期







### 密码模式

![](https://img-blog.csdnimg.cn/20200609205350862.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



使用该token进行访问

![](https://img-blog.csdnimg.cn/20200609205459395.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)

>可以看到，我们获取的token是一样的，因为当前用户的token没有过期





### 客户端模式

>此时不存在刷新token

![](https://img-blog.csdnimg.cn/20200609210149615.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



![](https://img-blog.csdnimg.cn/20200609210240918.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)





### 刷新token

>客户端模式没有刷新token

![](https://img-blog.csdnimg.cn/20200609212324932.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ0NzY2ODgz,size_16,color_FFFFFF,t_70)



我这里报了一个错误

```java
Handling error: IllegalStateException, UserDetailsService is required.
```

解决方法:

https://blog.csdn.net/qq_44766883/article/details/106651024