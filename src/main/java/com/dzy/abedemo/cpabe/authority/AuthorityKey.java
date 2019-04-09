package com.dzy.abedemo.cpabe.authority;

import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;

import java.io.*;
import java.util.Arrays;

public class AuthorityKey implements Serializable {
    private static final long serialVersionUID = 1235123412341245L;
    private String authorityID;
    private AuthPublicKey publicKey;
    private AuthSecretKey secretKey;


    public AuthorityKey(String authorityID) {
        this.authorityID = authorityID;
    }

    public String getAuthorityID() {
        return authorityID;
    }

    public void setPublicKey(AuthPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setSecretKey(AuthSecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public AuthPublicKey getPublicKey() {
        return publicKey;
    }

    public AuthSecretKey getSecretKey() {
        return secretKey;
    }

    public static void main(String[] args) {
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(512);
        String authorityID = "authority1";
        AuthorityKey authorityKey = EdgeTimeCPAbeV2.authoritySetup(authorityID, GP, "1", "2", "3", "4", "5");
        System.out.println();
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/" + authorityID + ".dat"));
            out.writeObject(authorityKey);
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        AuthorityKey readAuthKey = new AuthorityKey(authorityID);
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/" + authorityID + ".dat"));
            readAuthKey = (AuthorityKey) in.readObject();
            in.close();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("yyi=" + Arrays.toString(readAuthKey.getSecretKey().getYi()));
    }
}
