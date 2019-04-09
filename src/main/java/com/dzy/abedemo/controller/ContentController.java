package com.dzy.abedemo.controller;

import com.dzy.abedemo.domain.User;
import com.dzy.abedemo.service.ContentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import result.Result;

import java.security.Key;
import java.util.Arrays;

@Controller
@RequestMapping("/content")
public class ContentController {

    Logger log = LoggerFactory.getLogger(ContentController.class);

    @Autowired
    ContentService contentService;

    @RequestMapping("/to_input_content")
    public String toContentInput() {
        return "input_content";
    }

    @RequestMapping("/enc_content")
    @ResponseBody
    public Result<Boolean> symEncryptContent(@RequestParam("content") String content, Model model, User user) {
        if (user == null)
            log.info("user is null");
        model.addAttribute("user", user);
        Key symKey = contentService.generateSymKey();
        byte[] symEncCt = contentService.symEnc(content, symKey);
        log.info("key transform:=" + Arrays.toString(symKey.getEncoded()));
        return Result.success(true);
    }


}
