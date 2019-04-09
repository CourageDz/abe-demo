package com.dzy.abedemo.cpabe.test;


import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.ciphertext.AccessStructure;
import com.dzy.abedemo.cpabe.ciphertext.Ciphertext;
import com.dzy.abedemo.cpabe.ciphertext.LocaleCiphertext;
import com.dzy.abedemo.cpabe.ciphertext.Message;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.userKey.*;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SimulateEdgeCPAbe {
    private static Logger log = LoggerFactory.getLogger(EdgeTimeCPAbeV2.class);
    private String GPPATH = "F://edgeCPAbe/GlobalParam.dat";

    public void simGlobalSetUp(int lambda) throws Exception {
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(lambda);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/GlobalParam.dat"));
        out.writeObject(GP);
        out.close();
    }

    public AuthorityKey simAuthoritySetup(String authorityID, String... attributes) throws Exception {
        GlobalParam GP = getGP(GPPATH);
        AuthorityKey authorityKey = EdgeTimeCPAbeV2.authoritySetup(authorityID, GP, attributes);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/GlobalParam.dat"));
        //更新GP
        out.writeObject(GP);
        //写入属性机构秘钥
        out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/" + authorityID + "key.dat"));
        out.writeObject(authorityKey);
        out.close();
        return authorityKey;
    }

    public CertUid simUserRegister(String userID) throws Exception {
        GlobalParam GP = getGP(GPPATH);
        CertUid certUid = EdgeTimeCPAbeV2.userRegistry(GP, userID);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/UserCert.dat"));
        out.writeObject(certUid);
        out.close();
        return certUid;
    }

    public String simEncrypt(AccessStructure arho) throws Exception {
        GlobalParam GP = getGP(GPPATH);
        Message m = EdgeTimeCPAbeV2.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);
        Ciphertext ct = EdgeTimeCPAbeV2.normalEncrypt(m, arho, GP);
        String fID = ct.getfID();
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/ciphertext.dat"));
        out.writeObject(ct);
        out.close();
        return fID;
    }

    public String simAuthKeyGen(String authorityID, String userID, String... attributes) throws Exception {
        String AAKeyPath = "F://edgeCPAbe/" + authorityID + "key.dat";
        GlobalParam GP = getGP(GPPATH);
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(AAKeyPath));
        AuthorityKey authorityKey = (AuthorityKey) in.readObject();
        in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/UserCert.dat"));
        CertUid certUid = (CertUid) in.readObject();
        in.close();
        UserAuthorityKey uak = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityID, authorityKey.getSecretKey(), certUid, attributes);
        String userAuthKeyPath = "F://edgeCPAbe/" + userID + authorityID + ".dat";
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(userAuthKeyPath));
        out.writeObject(uak);
        out.close();
        return userAuthKeyPath;
    }

    public Userkeys simUserKeyGen(List<String> AuthKeys, String userID, CertUid certUid) throws Exception {
        GlobalParam GP = getGP(GPPATH);
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(AuthKeys.get(0)));
        List<UserAuthorityKey> uAKS = new ArrayList<>();
        for (String authKeyPath : AuthKeys) {
            in = new ObjectInputStream(new FileInputStream(authKeyPath));
            UserAuthorityKey uak = (UserAuthorityKey) in.readObject();
            uAKS.add(uak);
        }
        in.close();
        Userkeys userkeys = EdgeTimeCPAbeV2.keysGen(uAKS, userID, certUid, GP);
        return userkeys;
    }

    public byte[] simEdgeKeyGen(Userkeys userkeys, String fID) throws Exception {
        GlobalParam GP = getGP(GPPATH);
        UserSplitKeys usk = EdgeTimeCPAbeV2.edgeKeysGen(userkeys, GP, fID);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/edgeKeys.dat"));
        out.writeObject(usk.getEdgeKeys());
        out.close();
        return usk.getZ();
    }

    public void simEdgeDec() throws Exception {
        GlobalParam GP = getGP(GPPATH);
        ObjectInputStream in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/edgeKeys.dat"));
        EdgeKeys edgeKeys = (EdgeKeys) in.readObject();
        in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/ciphertext.dat"));
        Ciphertext ct = (Ciphertext) in.readObject();
        in.close();
        LocaleCiphertext lc = EdgeTimeCPAbeV2.outsourceDecrypt(ct, edgeKeys, GP);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/localCT.dat"));
        out.writeObject(lc);
        out.close();
    }

    public void simlocalDec(byte[] usk) throws Exception {
        GlobalParam GP = getGP(GPPATH);
        ObjectInputStream in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/localCT.dat"));
        LocaleCiphertext lc = (LocaleCiphertext) in.readObject();
        in.close();
        Message m = EdgeTimeCPAbeV2.localDecrypt(lc, usk, GP);
        System.out.println("解密后明文为：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);
    }

    public GlobalParam getGP(String path) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(path));
        GlobalParam GP = (GlobalParam) in.readObject();
        in.close();
        return GP;
    }
}
