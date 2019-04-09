package com.dzy.abedemo.cpabe.test;


import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.ciphertext.AccessStructure;
import com.dzy.abedemo.cpabe.ciphertext.Ciphertext;
import com.dzy.abedemo.cpabe.ciphertext.LocaleCiphertext;
import com.dzy.abedemo.cpabe.ciphertext.Message;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.timeParam.EncParam;
import com.dzy.abedemo.cpabe.timeParam.TimeKey;
import com.dzy.abedemo.cpabe.userKey.CertUid;
import com.dzy.abedemo.cpabe.userKey.UserAuthorityKey;
import com.dzy.abedemo.cpabe.userKey.UserSplitKeys;
import com.dzy.abedemo.cpabe.userKey.Userkeys;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class MyTestEdgeTimeCPAbe {
    private static Logger log = LoggerFactory.getLogger(MyTestEdgeTimeCPAbe.class);

    public static void main(String[] args) {
       /*for(int i=1;i<=10;i++){
            log.info("the num of Attributes in an Authority is 10,the num of Authorities is "+i);
            for(int j=1;j<=20;j++){
                log.info("the "+j+" Test start");
                testOsRegularEnc(10,i);
                log.info("the "+j+" Test end");
                log.info(" ");
            }
        }*/
//        testOsRegularEnc(20,10);
        for (int i = 0; i <= 10; i++) {
            log.info("the num of Attributes in an Authority is 10,the num of Authorities is 10,each Time AA the time Atts is 5，Time AA num is " + i);
            for (int j = 1; j <= 20; j++) {
                log.info("the " + j + " Test start");
                testOsTimeAuthCPAbe(10, 10, i, 5);
                log.info("the " + j + " Test end");
                log.info(" ");
                System.gc();
            }
        }

//        testOsTimeAuthCPAbe(10,10,10,10);
//        testOsTimeAuthCPAbe(10,10,10,5);
//        testOutsourcedCPAbe();
//        testTimeOutsourcedCPAbe();
    }

    public static void testOutsourcedCPAbe() {
        int lambda = 512;
        //Global Setup
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(lambda);
        //Authorities Setup
        String authority1ID = "authority1";
        String authority2ID = "authority2";


        AuthorityKey authorityKey1 = EdgeTimeCPAbeV2.authoritySetup(authority1ID, GP, "a");
        AuthorityKey authorityKey2 = EdgeTimeCPAbeV2.authoritySetup(authority2ID, GP, "c", "d", "e");
        //Generate UserKey
        String user1ID = "user1";
        CertUid certUid = EdgeTimeCPAbeV2.userRegistry(GP, user1ID);

        //Ciphertext generated
        Message m = EdgeTimeCPAbeV2.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);
        String policy = "and and a a or c and a e";
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);

        String fID = EdgeTimeCPAbeV2.generateRandomFid();


        Ciphertext ct = EdgeTimeCPAbeV2.normalEncrypt(m, arho, GP);

        //Userkey generate
        UserAuthorityKey uAK1 = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityKey1.getAuthorityID(), authorityKey1.getSecretKey(), certUid, "a");
        UserAuthorityKey uAK2 = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityKey2.getAuthorityID(), authorityKey2.getSecretKey(), certUid, "d", "e");

        List<UserAuthorityKey> uAKS = new ArrayList<>();
        uAKS.add(uAK1);
        uAKS.add(uAK2);
//        uAKS.add(uAK3);
        Userkeys userkeys = EdgeTimeCPAbeV2.keysGen(uAKS, user1ID, fID, certUid, GP);

        //decrypt CT
        Date t1 = new Date();
        Message decM = EdgeTimeCPAbeV2.decrypt(ct, userkeys, GP);
        System.out.println("解密后明文为：" + Arrays.toString(decM.m) + "\n长度为：" + decM.m.length);
        Date t2 = new Date();
        System.out.println("dec Time =" + (t2.getTime() - t1.getTime()));
    }

    public static void testTimeOutsourcedCPAbe() {
        int lambda = 512;
        //Global Setup
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(lambda);
        //Authorities Setup
        String authority1ID = "authority1";
        String authority2ID = "authority2";


        AuthorityKey authorityKey1 = EdgeTimeCPAbeV2.authoritySetup(authority1ID, GP, "a", "b");
        AuthorityKey authorityKey2 = EdgeTimeCPAbeV2.authoritySetup(authority2ID, GP, "c", "d", "e");
        //Generate UserKey
        String user1ID = "user1";
        CertUid certUid = EdgeTimeCPAbeV2.userRegistry(GP, user1ID);

        //Ciphertext generated
        Message m = EdgeTimeCPAbeV2.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);
        String policy = "and and at at  or c and dt et";
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);
        Date t1 = new Date();

        String fID = EdgeTimeCPAbeV2.generateRandomFid();
        Date begin = new Date(System.currentTimeMillis() - 100000);
        Date end = new Date(System.currentTimeMillis() + 100000);

        EncParam encParam1 = EdgeTimeCPAbeV2.genEncParam(GP, fID, begin, end, authority1ID, "a");
        EncParam encParam2 = EdgeTimeCPAbeV2.genEncParam(GP, fID, begin, end, authority2ID, "d", "e");
        List<EncParam> encParams = new ArrayList<>();
        encParams.add(encParam1);
        encParams.add(encParam2);

        Map<String, byte[]> encryptParams = EdgeTimeCPAbeV2.extractEncParam(encParams);
        Ciphertext ct = EdgeTimeCPAbeV2.timeEncrypt(m, fID, arho, GP, encryptParams);

        //Userkey generate
        UserAuthorityKey uAK1 = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityKey1.getAuthorityID(), authorityKey1.getSecretKey(), certUid, "a");
        UserAuthorityKey uAK2 = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityKey2.getAuthorityID(), authorityKey2.getSecretKey(), certUid);
//        UserAuthorityKey uAK3 =EdgeCPAbe.userAuthKeyGen(user1ID,GP,authorityKey3,userkeys);

        TimeKey ctTimeKey1 = EdgeTimeCPAbeV2.timeKeysGen(encParam1.getfID(), certUid, encParam1.getAaEncParam(), authorityKey1.getSecretKey(), GP, "a");
        TimeKey ctTimeKey2 = EdgeTimeCPAbeV2.timeKeysGen(encParam2.getfID(), certUid, encParam2.getAaEncParam(), authorityKey2.getSecretKey(), GP, "d", "e");
        uAK1.getUserTimeKeys().put(fID, ctTimeKey1);
        uAK2.getUserTimeKeys().put(fID, ctTimeKey2);

        List<UserAuthorityKey> uAKS = new ArrayList<>();
        uAKS.add(uAK1);
        uAKS.add(uAK2);
//        uAKS.add(uAK3);
        Userkeys userkeys = EdgeTimeCPAbeV2.keysGen(uAKS, user1ID, fID, certUid, GP);

        //decrypt CT
        Message decM = EdgeTimeCPAbeV2.decrypt(ct, userkeys, GP);
        System.out.println("解密后明文为：" + Arrays.toString(decM.m) + "\n长度为：" + decM.m.length);
        Date t2 = new Date();
        System.out.println("dec Time =" + (t2.getTime() - t1.getTime()));
    }

    public static void testOsRegularEnc(int n, int aAaTTNum) {
        int lambda = 512;
        //Global Setup
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(lambda);
        //Authorities Setup
        String authoritys[] = new String[n];
        AuthorityKey authorityKeys[] = new AuthorityKey[n];
        String attributes[][] = new String[n][aAaTTNum];

        long AASetupTimeSum = 0;
        for (int i = 0; i < n; i++) {
            authoritys[i] = "authority" + (i + 1);
            for (int j = 0; j < aAaTTNum; j++) {
                int num = i * aAaTTNum + j;
                attributes[i][j] = "" + num;
            }
            long AASetupTime = System.nanoTime();
            authorityKeys[i] = EdgeTimeCPAbeV2.authoritySetup(authoritys[i], GP, attributes[i]);
            AASetupTimeSum += System.nanoTime() - AASetupTime;
        }
        log.info("Average AA Setup Time = " + (AASetupTimeSum * 1.0 / (n * 1000000)) + " ms");

        //policy generated
        Message m = EdgeTimeCPAbeV2.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);
        String policy = PolicyTest.genPolicy(n * aAaTTNum, 0);
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);

        //Ciphertext generated
        long startTime = System.nanoTime();
        Ciphertext ct = EdgeTimeCPAbeV2.normalEncrypt(m, arho, GP);
        log.info("enc time= " + (System.nanoTime() - startTime) * 1.0 / 1000000 + " ms");
        //User register
        String user1ID = "user1";
        CertUid certUid = EdgeTimeCPAbeV2.userRegistry(GP, user1ID);
        //gen UserKeys
        UserAuthorityKey uAKS[] = new UserAuthorityKey[n];

        long UserAATimeSum = 0;
        for (int i = 0; i < n; i++) {
            long aaT = System.nanoTime();
            uAKS[i] = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityKeys[i].getAuthorityID(), authorityKeys[i].getSecretKey(), certUid, attributes[i]);
            UserAATimeSum += System.nanoTime() - aaT;
        }
        log.info("Average AAkeyGen Time= " + (UserAATimeSum * 1.0 / (n * 1000000)) + " ms");

        List<UserAuthorityKey> uAKList = Arrays.asList(uAKS);
        Userkeys userkeys = EdgeTimeCPAbeV2.keysGen(uAKList, user1ID, ct.getfID(), certUid, GP);
        //transform userKeys
        long transformKeyTime = System.nanoTime();
        UserSplitKeys usk = EdgeTimeCPAbeV2.edgeKeysGen(userkeys, GP, ct.getfID());
        log.info("Transform key Time= " + ((System.nanoTime() - transformKeyTime) * 1.0 / 1000000) + " ms");

        //OutsourcedDecrypt CT
        long outSourceTime = System.nanoTime();
        LocaleCiphertext lc = EdgeTimeCPAbeV2.outsourceDecrypt(ct, usk.getEdgeKeys(), GP);
        log.info("partial dec time = " + (System.nanoTime() - outSourceTime) * 1.0 / 1000000 + " ms");
        //local Dec
        long localDecTime = System.nanoTime();
        Message decM = EdgeTimeCPAbeV2.localDecrypt(lc, usk.getZ(), GP);
        log.info("local dec time = " + (System.nanoTime() - localDecTime) * 1.0 / 1000000 + " ms");
        System.out.println("解密后明文为：" + Arrays.toString(decM.m) + "\n长度为：" + decM.m.length);
    }

    //时间授权机构个数变化
    public static void testOsTimeAuthCPAbe(int AANums, int AttNums, int tAANums, int tAttNums) {
        int lambda = 512;
        //Global Setup
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(lambda);
        //Authorities Setup
        String authoritys[] = new String[AANums];
        AuthorityKey authorityKeys[] = new AuthorityKey[AANums];
        String attributes[][] = new String[AANums][AttNums];

        long AASetupTimeSum = 0;
        for (int i = 0; i < AANums; i++) {
            authoritys[i] = "authority" + (i + 1);
            for (int j = 0; j < AttNums; j++) {
                int num = i * AttNums + j;
                attributes[i][j] = "" + num;
            }
            long AASetupTime = System.nanoTime();
            authorityKeys[i] = EdgeTimeCPAbeV2.authoritySetup(authoritys[i], GP, attributes[i]);
            AASetupTimeSum += System.nanoTime() - AASetupTime;
        }
        log.info("Average AA Setup Time = " + (AASetupTimeSum * 1.0 / (AANums * 1000000)) + " ms");

        //Time policy generated
        Message m = EdgeTimeCPAbeV2.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);
        String policy = PolicyTest.genAuthTimePolicy(AANums, AttNums, tAANums, tAttNums, 0);
        System.out.println(policy);
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);
        String fID = EdgeTimeCPAbeV2.generateRandomFid();
        //Time Param Gen
        List<EncParam> encParamsList = new ArrayList<>();
        EncParam[] encParams = new EncParam[tAANums];
        String[][] timeAtts = new String[tAANums][tAttNums];
        long genEncParamTimes = 0;
        for (int i = 0; i < tAANums; i++) {
            Date begin = new Date(System.currentTimeMillis() - 100000);
            Date end = new Date(System.currentTimeMillis() + 100000);
            timeAtts[i] = Arrays.copyOf(attributes[i], tAttNums);

            long encParamTime = System.nanoTime();
            encParams[i] = EdgeTimeCPAbeV2.genEncParam(GP, fID, begin, end, authoritys[i], timeAtts[i]);
            genEncParamTimes += System.nanoTime() - encParamTime;
        }
        encParamsList = Arrays.asList(encParams);

        //提取用于加密的时间参数
        long extractEncParam = System.nanoTime();
        Map<String, byte[]> encryptParams = EdgeTimeCPAbeV2.extractEncParam(encParamsList);
        genEncParamTimes += System.nanoTime() - extractEncParam;
        log.info("gen EncParam Time =" + genEncParamTimes * 1.0 / 1000000 + " ms");

        //基于时间参数的加密
        long encStartTime = System.nanoTime();
        Ciphertext ct = EdgeTimeCPAbeV2.timeEncrypt(m, fID, arho, GP, encryptParams);
        log.info("enc time= " + (System.nanoTime() - encStartTime) * 1.0 / 1000000 + " ms");

        //用户注册
        String userID = "user1";
        CertUid certUid = EdgeTimeCPAbeV2.userRegistry(GP, userID);

        //Userkey generate
        UserAuthorityKey uAKS[] = new UserAuthorityKey[AANums];

        long UserAATimeSum = 0;

        TimeKey[] timeKeys = new TimeKey[tAANums];
        for (int i = 0; i < AANums; i++) {

            long aaT = System.nanoTime();
            if (i < tAANums) {
                String[] normalAtts = Arrays.copyOfRange(attributes[i], tAttNums, AANums);
                uAKS[i] = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityKeys[i].getAuthorityID(), authorityKeys[i].getSecretKey(), certUid, normalAtts);
                timeKeys[i] = EdgeTimeCPAbeV2.timeKeysGen(fID, certUid, encParams[i].getAaEncParam(), authorityKeys[i].getSecretKey(), GP, timeAtts[i]);
                uAKS[i].getUserTimeKeys().put(fID, timeKeys[i]);
                UserAATimeSum += System.nanoTime() - aaT;
            } else {
                uAKS[i] = EdgeTimeCPAbeV2.userAuthKeyGen(GP, authorityKeys[i].getAuthorityID(), authorityKeys[i].getSecretKey(), certUid, attributes[i]);
            }
        }
        log.info("Average TimekeyGen Time= " + (UserAATimeSum * 1.0 / (tAANums * 1000000)) + " ms");

        List<UserAuthorityKey> uAKList = Arrays.asList(uAKS);
        Userkeys userkeys = EdgeTimeCPAbeV2.keysGen(uAKList, userID, ct.getfID(), certUid, GP);

        //transform userKeys
        long transformKeyTime = System.nanoTime();
        UserSplitKeys usk = EdgeTimeCPAbeV2.edgeKeysGen(userkeys, GP, fID);
        log.info("Transform key Time= " + ((System.nanoTime() - transformKeyTime) * 1.0 / 1000000) + " ms");

        //OutsourcedDecrypt CT
        long outSourceTime = System.nanoTime();
        LocaleCiphertext lc = EdgeTimeCPAbeV2.outsourceDecrypt(ct, usk.getEdgeKeys(), GP);
        log.info("partial dec time = " + (System.nanoTime() - outSourceTime) * 1.0 / 1000000 + " ms");
        //local Dec
        long localDecTime = System.nanoTime();
        Message decM = EdgeTimeCPAbeV2.localDecrypt(lc, usk.getZ(), GP);
        log.info("local dec time = " + (System.nanoTime() - localDecTime) * 1.0 / 1000000 + " ms");
        System.out.println("解密后明文为：" + Arrays.toString(decM.m) + "\n长度为：" + decM.m.length);
    }
}
