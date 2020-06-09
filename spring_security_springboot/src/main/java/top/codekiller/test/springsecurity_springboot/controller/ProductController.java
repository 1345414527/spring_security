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
