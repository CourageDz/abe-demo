package com.dzy.abedemo.exception;

import result.CodeMsg;

public class GlobalException extends RuntimeException {
    public static final long serialVersionUID = 1L;
    private CodeMsg cm;

    public GlobalException(CodeMsg cm) {
        super(cm.toString());
        this.cm = cm;
    }

    public CodeMsg getCm() {
        return cm;
    }
}
