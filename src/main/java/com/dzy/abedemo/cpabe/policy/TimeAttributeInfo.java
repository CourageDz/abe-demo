package com.dzy.abedemo.cpabe.policy;

public class TimeAttributeInfo extends AttributeInfo {
    private byte[] timeParam;

    public TimeAttributeInfo(int index, byte[] lambda, byte[] attRx, boolean isTime, byte[] timeParam) {
        super(index, lambda, attRx, isTime);
        this.timeParam = timeParam;
    }

    public TimeAttributeInfo(int index, byte[] lambda, byte[] attRx, boolean isTime) {
        super(index, lambda, attRx, isTime);
    }

    public byte[] getTimeParam() {
        return timeParam;
    }

    public void setTimeParam(byte[] timeParam) {
        this.timeParam = timeParam;
    }
}
