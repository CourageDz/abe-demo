package com.dzy.abedemo.service;

import com.dzy.abedemo.dao.UserDao;
import com.dzy.abedemo.domain.User;
import com.dzy.abedemo.exception.GlobalException;
import com.dzy.abedemo.vo.LoginVo;
import org.springframework.stereotype.Service;
import result.CodeMsg;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

@Service
public class UserService {
    @Resource
    UserDao userDao;

    public boolean login(HttpServletResponse response, LoginVo loginVo) {
        if (loginVo == null)
            throw new GlobalException(CodeMsg.LOGIN_ERROR);

        String mobile = loginVo.getMobile();
        String formPass = loginVo.getPassword();
        long userMobile = Long.parseLong(mobile);
        User user = userDao.getByID(userMobile);
        if (user == null) {
            throw new GlobalException(CodeMsg.LOGIN_USER_ERROR);
        }
        String dbPass = user.getPassword();
        if (!formPass.equals(dbPass)) {
            throw new GlobalException(CodeMsg.PASSWORD_ERROR);
        }
        return true;
    }
}
