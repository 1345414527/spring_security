package top.codekiller.test.springsecurity.utils;

import lombok.Data;

import java.util.Date;

/**
 * @author codekiller
 * @date 2020/6/8 18:52
 * @description 载荷
 */
@Data
public class Payload<T> {
    private String id;
    private T userInfo;
    private Date expiration;
}
