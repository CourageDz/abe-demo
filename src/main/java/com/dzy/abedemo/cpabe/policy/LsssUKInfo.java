package com.dzy.abedemo.cpabe.policy;

public class LsssUKInfo {
    private AttributeInfo oldAtt;
    private AttributeInfo newAtt;
    private byte[] aAPK2;

    public LsssUKInfo(AttributeInfo oldAtt, AttributeInfo newAtt, byte[] aAPK2) {
        this.oldAtt = oldAtt;
        this.newAtt = newAtt;
        this.aAPK2 = aAPK2;
    }

    public AttributeInfo getOldAtt() {
        return oldAtt;
    }

    public AttributeInfo getNewAtt() {
        return newAtt;
    }

    public byte[] getaAPK2() {
        return aAPK2;
    }


}
