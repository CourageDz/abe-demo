package com.dzy.abedemo.cpabe.userKey;


public class UserSplitKeys {
    private static final long serialVersionUID = 1L;
    String userId;
    private byte[] z;
    private EdgeKeys edgeKeys;


    public UserSplitKeys(String UserId) {
        this.userId = UserId;
        edgeKeys = new EdgeKeys();
    }

    public byte[] getZ() {
        return z;
    }

    public void setZ(byte[] z) {
        this.z = z;
    }

    public EdgeKeys getEdgeKeys() {
        return edgeKeys;
    }

    public void setEdgeKeys(EdgeKeys edgeKeys) {
        this.edgeKeys = edgeKeys;
    }
}
