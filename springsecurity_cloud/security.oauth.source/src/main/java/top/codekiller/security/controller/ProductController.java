package top.codekiller.security.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author codekiller
 * @date 2020/6/9 17:16
 * @description DES
 */
@RestController
@RequestMapping("/product")
public class ProductController {

    @Secured("ROLE_ADMIN")
    @GetMapping("/findAll")
    public String findAll(){
        return "参评列表查询成功";
    }
}
