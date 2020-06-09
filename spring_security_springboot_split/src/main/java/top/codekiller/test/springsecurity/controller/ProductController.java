package top.codekiller.test.springsecurity.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author codekiller
 * @date 2020/6/8 10:41
 * @description DES
 */
@RestController
@RequestMapping("/product")
public class ProductController {

    @Secured({"ROLE_ADMIN"})  //控制权限访问
    @RequestMapping("/findAll")
    public String findAll(){
        return "product-list";
    }
}
