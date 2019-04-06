package com.dzy.abedemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;

@SpringBootApplication
public class AbeDemoApplication {
    @RequestMapping("/")
    public static String index(){
        return "hello";
    }

    public static void main(String[] args) {
        SpringApplication.run(AbeDemoApplication.class, args);
    }

}
