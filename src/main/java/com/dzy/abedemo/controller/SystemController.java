package com.dzy.abedemo.controller;

import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import com.dzy.abedemo.service.SystemService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import result.Result;

@Controller
@RequestMapping("/system")
public class SystemController {
    private static Logger logger = LoggerFactory.getLogger(SystemController.class);

    @Autowired
    SystemService systemService;

    @RequestMapping("/init")
    @ResponseBody
    public Result<Boolean> systemInit() {
        GlobalParam gp = systemService.genGlobalSystem();
        int authorityNumber = 10;
        int attNumbers = 5;
        AuthorityKey[] aks = systemService.genAuthorityKeys(authorityNumber, attNumbers);
//        logger.info("g in gp:=" + Arrays.toString(gp.getG()));
        return Result.success(true);
    }

    @RequestMapping("/test")
    @ResponseBody
    public Result<Boolean> testGP() {
        String fileName = "GlobalParam.dat";
        try {
            GlobalParam gp = (GlobalParam) EdgeTimeCPAbeV2.readJavaPojoFromFile(GlobalParam.class, SystemService.FILE_PATH, fileName);
//            logger.info("g in gp:=" + Arrays.toString(gp.getG()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Result.success(true);
    }
}
