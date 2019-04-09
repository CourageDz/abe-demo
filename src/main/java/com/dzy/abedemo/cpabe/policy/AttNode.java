package com.dzy.abedemo.cpabe.policy;

public class AttNode {
    private int oldIndex;
    private int type;

    public AttNode(int oldIndex, int type) {
        this.oldIndex = oldIndex;
        this.type = type;
    }

    public int getOldIndex() {
        return oldIndex;
    }

    public int getType() {
        return type;
    }
}
