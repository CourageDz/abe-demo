package com.dzy.abedemo.cpabe.userKey;


import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.timeParam.TimeKey;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class UserAuthorityKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<String, UserAttributeKey> userAttKeys;
    private Map<String, TimeKey> userTimeKeys;
    private final String authority;
    private byte[] kjk;
    private byte[] ljk;
//    private byte[] ljk2;


    public UserAuthorityKey(String authority) {
        this.authority = authority;
        userAttKeys = new HashMap<>();
        userTimeKeys = new HashMap<>();
    }

    public Map<String, UserAttributeKey> getUserAttKeys() {
        return userAttKeys;
    }

    public void addKey(UserAttributeKey ak) {
        userAttKeys.put(ak.getAttribute(), ak);
    }

    public Set<String> getAttributes() {
        return userAttKeys.keySet();
    }

    public Set<String> getTimeAttributes(String fID) {
        TimeKey tk = userTimeKeys.get(fID);
        if (tk == null)
            return null;
        else
            return tk.getUserAttKeys().keySet();
    }

    public byte[] getKjk() {
        return kjk;
    }

    public void setKjk(byte[] kjk) {
        this.kjk = kjk;
    }

    public String getAuthority() {
        return authority;
    }

    public byte[] getLjk() {
        return ljk;
    }

    public void setLjk(byte[] ljk) {
        this.ljk = ljk;
    }

    public Map<String, TimeKey> getUserTimeKeys() {
        return userTimeKeys;
    }

    public UserAttributeKey getByAttribute(String attribute) {
        return userAttKeys.get(attribute);
    }

    public static void main(String[] args) {
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(512);
        String authorityID = "authority1";
        AuthorityKey authorityKey = EdgeTimeCPAbeV2.authoritySetup(authorityID, GP, "1", "2", "3");
        String userID = "user1";
        CertUid certUid = EdgeTimeCPAbeV2.userRegistry(GP, userID);
        UserAuthorityKey uak = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityID, authorityKey.getSecretKey(), certUid, "1", "2");
        System.out.println("ljk=" + Arrays.toString(uak.getLjk()));
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/" + userID + authorityID + ".dat"));
            out.writeObject(uak);
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        UserAuthorityKey readUak = new UserAuthorityKey(authorityID);
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/" + userID + authorityID + ".dat"));
            readUak = (UserAuthorityKey) in.readObject();
            in.close();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("ljkk=" + Arrays.toString(readUak.getLjk()));
    }
}
