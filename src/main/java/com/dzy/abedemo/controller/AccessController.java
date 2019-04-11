package com.dzy.abedemo.controller;

import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.userKey.CertUid;
import com.dzy.abedemo.cpabe.userKey.UserAuthorityKey;
import com.dzy.abedemo.domain.User;
import com.dzy.abedemo.service.AccessService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import result.CodeMsg;
import result.Result;

@Controller
@RequestMapping("/access")
public class AccessController {

    @Autowired
    AccessService accessService;

    @RequestMapping("/to_input_du")
    public String toContentInput() {
        return "input_identity";
    }

    @RequestMapping("/du_init")
    @ResponseBody
    public Result<Boolean> initDataUser(@RequestParam("duAttributes") String duAttribtues, Model model, User user) {
        model.addAttribute("user", user);
        long userId = user.getId();
        GlobalParam gp = accessService.getGlobalParam();
        if (gp == null)
            return Result.error(CodeMsg.GP_FILE_NOT_EXISTS);

        CertUid certUid = accessService.registerUser(gp, userId);
        UserAuthorityKey uAKS[] = accessService.getUserAAKeys(gp, duAttribtues);

        return Result.success(true);
    }
}
