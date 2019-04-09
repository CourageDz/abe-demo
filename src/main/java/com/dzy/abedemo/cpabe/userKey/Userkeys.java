package com.dzy.abedemo.cpabe.userKey;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Userkeys {
    private static final long serialVersionUID = 1L;
    private String userID;
    private Map<String, UserAuthorityKey> userAuthKeys;
    private Set<String> timeAttributes;
    private Set<String> attributes;
    private CertUid userCert;
    private byte[] rj;


    public Userkeys(String UserId) {
        this.userID = UserId;
        this.userAuthKeys = new HashMap<>();
        this.attributes = new HashSet<>();
        this.timeAttributes = new HashSet<>();
    }

    public void addKey(UserAuthorityKey ak) {
        userAuthKeys.put(ak.getAuthority(), ak);
    }

    public Set<String> getAuthorities() {
        return userAuthKeys.keySet();
    }

    public String getUserID() {
        return userID;
    }

    public Map<String, UserAuthorityKey> getUserAuthKeys() {
        return userAuthKeys;
    }

    public void addAttributes(Set<String> authAttributes) {
        this.attributes.addAll(authAttributes);
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public void addTimeAttributes(Set<String> authAttributes) {
        this.timeAttributes.addAll(authAttributes);
    }

    public Set<String> getTimeAttributes() {
        return timeAttributes;
    }

    public CertUid getUserCert() {
        return userCert;
    }

    public void setUserCert(CertUid userCert) {
        this.userCert = userCert;
    }

    public byte[] getRj() {
        return rj;
    }

    public void setRj(byte[] rj) {
        this.rj = rj;
    }


    public void setAttributes(Set<String> attributes) {
        this.attributes = attributes;
    }

}
