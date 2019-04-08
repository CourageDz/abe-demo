package com.dzy.abedemo.controller;

import com.dzy.abedemo.service.UserService;
import com.dzy.abedemo.vo.LoginVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import result.Result;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@Controller
@RequestMapping("/login")
public class LoginController {
    @Autowired
    UserService userService;

    @RequestMapping("/to_login")
    public String toLogin() {
        return "login";
    }

    @RequestMapping("/do_login")
    @ResponseBody
    public Result<Boolean> do_login(HttpServletResponse response, @Valid LoginVo vo) {
        //登录
        userService.login(response, vo);
        return Result.success(true);
    }
}
