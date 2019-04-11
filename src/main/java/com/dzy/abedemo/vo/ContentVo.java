package com.dzy.abedemo.vo;

import javax.validation.constraints.NotNull;

public class ContentVo {
    @NotNull
    private String content;
    @NotNull
    private String policy;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }
}
