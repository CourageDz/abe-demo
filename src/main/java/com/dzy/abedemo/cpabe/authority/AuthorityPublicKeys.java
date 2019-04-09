package com.dzy.abedemo.cpabe.authority;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class AuthorityPublicKeys implements Serializable {
    private static final long serialVersionUID = 1L;
    // map attribute to authority
    private Map<String, String> authorityMap;
    //map authority to authpublicKey
    private Map<String, AuthPublicKey> aAPKMap;


    public AuthorityPublicKeys() {
        authorityMap = new HashMap<>();
        aAPKMap = new HashMap<>();
    }

    public AuthPublicKey getAPKByAttr(String attribute) {
        if (!authorityMap.containsKey(attribute))
            throw new IllegalArgumentException("属性不存在于属性机构中");
        String authorityID = authorityMap.get(attribute);
        AuthPublicKey aPK = aAPKMap.get(authorityID);
        return aPK;
    }

    public Map<String, String> getTMap() {
        return authorityMap;
    }


    public Map<String, AuthPublicKey> getaAPKMap() {
        return aAPKMap;
    }


}
