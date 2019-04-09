package com.dzy.abedemo.cpabe.ciphertext;

public class Attribute extends TreeNode {
    private static final long serialVersionUID = 1L;
    private String name;
    private int x;
    private boolean isTimeLimited;

    public Attribute(String name) {
        if (name.endsWith("t")) {
            this.name = name.substring(0, name.length() - 1);
            isTimeLimited = true;
        } else
            this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    public int getX() {
        return x;
    }

    public void setX(int x) {
        this.x = x;
    }

    public boolean isTimeLimited() {
        return isTimeLimited;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + x;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof Attribute))
            return false;
        Attribute other = (Attribute) obj;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        return x == other.x;
    }
}
