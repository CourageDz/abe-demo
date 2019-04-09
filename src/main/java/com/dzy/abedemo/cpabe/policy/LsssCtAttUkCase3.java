package com.dzy.abedemo.cpabe.policy;

public class LsssCtAttUkCase3 extends LsssCtAttUk {
    private byte[] uk3;

    public LsssCtAttUkCase3(byte[] k1, byte[] k2, byte[] uk3) {
        super(k1, k2);
        this.uk3 = uk3;
    }

    public byte[] getUk3() {
        return uk3;
    }
}

