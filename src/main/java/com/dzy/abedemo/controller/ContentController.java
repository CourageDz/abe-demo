package com.dzy.abedemo.controller;

import com.dzy.abedemo.cpabe.ciphertext.Ciphertext;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.domain.User;
import com.dzy.abedemo.service.ContentService;
import com.dzy.abedemo.service.SystemService;
import com.dzy.abedemo.vo.ContentVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import result.Result;

import javax.validation.Valid;
import java.security.Key;
import java.util.Arrays;

@Controller
@RequestMapping("/content")
public class ContentController {

    Logger log = LoggerFactory.getLogger(ContentController.class);

    @Autowired
    ContentService contentService;
    @Autowired
    SystemService systemService;

    @RequestMapping("/to_input_content")
    public String toContentInput() {
        return "input_content";
    }

    @RequestMapping("/enc_content")
    @ResponseBody
    public Result<Boolean> symEncryptContent(@Valid ContentVo contentVo, Model model, User user) {
        if (user == null)
            log.info("user is null");
        model.addAttribute("user", user);
        String content = contentVo.getContent();
        String policy = contentVo.getPolicy();

        Key symKey = contentService.generateSymKey();
        byte[] symEncCt = contentService.symEnc(content, symKey);
        GlobalParam GP = systemService.genGlobalSystem();
        Ciphertext ciphertext = contentService.symKeyEnc(symKey.getEncoded(), policy, GP);
        log.info("key transform:=" + Arrays.toString(symKey.getEncoded()));
        return Result.success(true);
    }


}
