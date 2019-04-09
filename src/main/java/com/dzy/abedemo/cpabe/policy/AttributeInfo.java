package com.dzy.abedemo.cpabe.policy;

public class AttributeInfo {
    private int index;
    private byte[] lambda;
    private byte[] attRx;
    private boolean isTime;

    public AttributeInfo() {
    }

    public AttributeInfo(int index, byte[] lambda, byte[] attRx, boolean isTime) {
        this.index = index;
        this.lambda = lambda;
        this.attRx = attRx;
        this.isTime = isTime;
    }

    public int getIndex() {
        return index;
    }

    public byte[] getLambda() {
        return lambda;
    }

    public byte[] getAttRx() {
        return attRx;
    }

    public boolean isTime() {
        return isTime;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public void setLambda(byte[] lambda) {
        this.lambda = lambda;
    }

    public void setAttRx(byte[] attRx) {
        this.attRx = attRx;
    }

    public void setTime(boolean time) {
        isTime = time;
    }
}
