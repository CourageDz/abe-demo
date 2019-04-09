package com.dzy.abedemo.cpabe.policy;

import com.dzy.abedemo.cpabe.authority.AuthPublicKey;
import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.authority.AuthorityPublicKeys;
import com.dzy.abedemo.cpabe.ciphertext.AccessStructure;
import com.dzy.abedemo.cpabe.ciphertext.Ciphertext;
import com.dzy.abedemo.cpabe.ciphertext.Message;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.test.PolicyTest;
import com.dzy.abedemo.cpabe.timeParam.EncParam;
import com.dzy.abedemo.cpabe.userKey.CertUid;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class PolicyCompare {
    private GlobalParam GP;
    private Pairing pairing;

    public PolicyCompare(GlobalParam GP) {
        this.GP = GP;
        this.pairing = PairingFactory.getPairing(GP.getPairingParameters());
    }

    private static Logger log = LoggerFactory.getLogger(PolicyCompare.class);

    public Ciphertext encrypt(Message message, String fID, AccessStructure arho, Map<String, byte[]> timeAttributes, EncInfo encInfo) {
        Ciphertext ct = new Ciphertext();
        ct.setfID(fID);
        AuthorityPublicKeys AKS = GP.getAPKS();
        Element M = pairing.getGT().newElementFromBytes(message.m).getImmutable();
        Element g = pairing.getG1().newElementFromBytes(GP.getG()).getImmutable();
        Element s = pairing.getZr().newRandomElement().getImmutable();

        List<Element> v = new ArrayList<>(arho.getL());
        v.add(s);

        for (int i = 1; i < arho.getL(); i++) {
            v.add(pairing.getZr().newRandomElement().getImmutable());
        }

        ct.setAccessStructure(arho);

        Element c0 = pairing.getGT().newOneElement();

        Element c1 = g.powZn(s);
        ct.setC1(c1.toBytes());

        Element gA = pairing.getG1().newElementFromBytes(GP.getGa()).getImmutable();
        Map<Integer, byte[]> attParam = encInfo.getTx();
        Map<Integer, byte[]> timeParam = encInfo.getTimeParam();

        Set<String> authorities = ct.getAuthorities();
        for (int i = 0; i < arho.getN(); i++) {
            Element lambdaX = EdgeTimeCPAbeV2.dotProduct(arho.getRow(i), v, pairing.getZr().newZeroElement(), pairing).getImmutable();

            Element rx = pairing.getZr().newRandomElement().getImmutable();
            boolean isTimeLimited = arho.rho(i).isTimeLimited();
            String attribute = arho.rho(i).getAttribute();
            String authorityID = AKS.getTMap().get(attribute);
            if (!authorities.contains(authorityID)) {
                authorities.add(authorityID);
                Element eggAi = pairing.getGT().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getEg1g1ai());
                c0.mul(eggAi);
            }

            attParam.put(i, rx.toBytes());
            Element gYi = pairing.getG1().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getG1yi()).getImmutable();
            Element attG1 = pairing.getG1().newElementFromBytes(attribute.getBytes()).getImmutable();

            ct.setC2(gA.powZn(lambdaX).mul(gYi.powZn(rx)).toBytes());

            Element c3x = g.powZn(rx.negate());
            ct.setC3(c3x.toBytes());

            if (isTimeLimited) {
                Element tx = pairing.getZr().newElementFromBytes(timeAttributes.get(attribute));
                timeParam.put(i, tx.toBytes());
                ct.setC4(attG1.powZn(rx).mul(gYi.powZn(rx.mul(tx))).toBytes());
            } else {
                ct.setC4(attG1.powZn(rx).mul(gYi.powZn(rx)).toBytes());
            }
        }
        /*for(String authority: authorities){
            Element eggAi = pairing.getGT().newElementFromBytes(AKS.getaAPKMap().get(authority).getEg1g1ai());
            c0.mul(eggAi);
        }*/
        ct.setC0(M.mul(c0.powZn(s)).toBytes());
        return ct;
    }

    public Ciphertext timeEncrypt(Message message, String fID, AccessStructure arho, Map<String, byte[]> timeAttributes, EncInfo encInfo) {
        Ciphertext ct = new Ciphertext();
        ct.setfID(fID);
        AuthorityPublicKeys AKS = GP.getAPKS();
        Element M = pairing.getGT().newElementFromBytes(message.m).getImmutable();
        Element g = pairing.getG1().newElementFromBytes(GP.getG()).getImmutable();
        Element s = pairing.getZr().newRandomElement().getImmutable();
        encInfo.setS(s.toBytes());

        List<Element> v = new ArrayList<>(arho.getL());
        v.add(s);

        for (int i = 1; i < arho.getL(); i++) {
            v.add(pairing.getZr().newRandomElement().getImmutable());
        }

        ct.setAccessStructure(arho);

        Element c0 = pairing.getGT().newOneElement();

        Element c1 = g.powZn(s);
        ct.setC1(c1.toBytes());

        Element gA = pairing.getG1().newElementFromBytes(GP.getGa()).getImmutable();
        Map<Integer, byte[]> attParam = encInfo.getTx();
        Map<Integer, byte[]> timeParam = encInfo.getTimeParam();
        Map<Integer, byte[]> lambdaParam = encInfo.getLambdaParam();

        List<Boolean> isTimes = encInfo.getIsTime();

        Set<String> authorities = ct.getAuthorities();
        for (int i = 0; i < arho.getN(); i++) {
            Element lambdaX = EdgeTimeCPAbeV2.dotProduct(arho.getRow(i), v, pairing.getZr().newZeroElement(), pairing).getImmutable();
            lambdaParam.put(i, lambdaX.toBytes());
            Element rx = pairing.getZr().newRandomElement().getImmutable();

            boolean isTimeLimited = arho.rho(i).isTimeLimited();
            String attribute = arho.rho(i).getAttribute();
            String authorityID = AKS.getTMap().get(attribute);
            if (!authorities.contains(authorityID)) {
                authorities.add(authorityID);
                Element eggAi = pairing.getGT().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getEg1g1ai());
                c0.mul(eggAi);
            }
            attParam.put(i, rx.toBytes());

            Element gYi = pairing.getG1().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getG1yi()).getImmutable();
            Element attG1 = pairing.getG1().newElementFromBytes(attribute.getBytes()).getImmutable();

            ct.setC2(gA.powZn(lambdaX).mul(gYi.powZn(rx)).toBytes());

            Element c3x = g.powZn(rx.negate());
            ct.setC3(c3x.toBytes());

            if (isTimeLimited) {
                Element tx = pairing.getZr().newElementFromBytes(timeAttributes.get(attribute));
                timeParam.put(i, tx.toBytes());
                isTimes.add(true);
                ct.setC4(attG1.powZn(rx).mul(gYi.powZn(rx.mul(tx))).toBytes());
            } else {
                ct.setC4(attG1.powZn(rx).mul(gYi.powZn(rx)).toBytes());
                isTimes.add(false);
            }
        }
        /*for(String authority: authorities){
            Element eggAi = pairing.getGT().newElementFromBytes(AKS.getaAPKMap().get(authority).getEg1g1ai());
            c0.mul(eggAi);
        }*/
        ct.setC0(M.mul(c0.powZn(s)).toBytes());
        return ct;
    }

    public Map<String, byte[]> extractEncParam(List<EncParam> encParams, Map<String, byte[]> aaFidTPs) {
        Map<String, byte[]> timeAttributes = new HashMap<>();
        for (EncParam encParam : encParams) {
            for (String attribute : encParam.getAaEncParam().getAttributes()) {
                timeAttributes.put(attribute, encParam.getParam());
            }
            aaFidTPs.put(encParam.getAaEncParam().getAuthority(), encParam.getParam());
        }
        return timeAttributes;
    }

    public void setupGenTimeAttUK(int AANums, int AttNums, int tAANums, int tAttNums) {
        //Authorities Setup
        String authoritys[] = new String[AANums];
        AuthorityKey authorityKeys[] = new AuthorityKey[AANums];
        String attributes[][] = new String[AANums][AttNums];

        for (int i = 0; i < AANums; i++) {
            authoritys[i] = "authority" + (i + 1);
            for (int j = 0; j < AttNums; j++) {
                int num = i * AttNums + j;
                attributes[i][j] = "" + num;
            }
            authorityKeys[i] = EdgeTimeCPAbeV2.authoritySetup(authoritys[i], GP, attributes[i]);
        }

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
        Map<String, byte[]> encryptParams = EdgeTimeCPAbeV2.extractEncParam(encParamsList);

        //基于时间参数的加密
        EncInfo encInfo = new EncInfo();
        Ciphertext ct = encrypt(m, fID, arho, encryptParams, encInfo);

        byte[] aAPK = GP.getAPKS().getaAPKMap().get(authoritys[0]).getG1yi();
        int[] uKAtts = {0, 1, 2, 3};

        long timeAttUKTime = System.nanoTime();
        TimeAttUK timeAttUK = genTimeAttUK(aAPK, encInfo, uKAtts);
        log.info("Gen timeAttUpdateKey time= " + (System.nanoTime() - timeAttUKTime) * 1.0 / 1000000 + " ms");

        long ctTimeAttUKTime = System.nanoTime();
        updateCtByTimeAttsUk(ct, timeAttUK.getUk_x());
        log.info("update ct by timeAttUpdateKey time= " + (System.nanoTime() - ctTimeAttUKTime) * 1.0 / 1000000 + " ms");
    }

    public TimeAttUK genTimeAttUK(byte[] aAPK, EncInfo encInfo, int... attributes) {
        Element newRj = pairing.getZr().newRandomElement();
        Element g = pairing.getG1().newElementFromBytes(GP.getG()).getImmutable();
        Element uk1 = g.powZn(newRj);
        TimeAttUK timeAttUK = new TimeAttUK(uk1.toBytes());
        Map<Integer, byte[]> attsUK = timeAttUK.getUk_x();

        Element aaPK2 = pairing.getG1().newElementFromBytes(aAPK).getImmutable();
        for (int index : attributes) {
            Element rx = pairing.getZr().newElementFromBytes(encInfo.getTx().get(index)).getImmutable();
            Element oldRj = pairing.getZr().newElementFromBytes(encInfo.getTimeParam().get(index));
            Element uk2 = aaPK2.powZn(rx.mul(newRj.sub(oldRj)));
            attsUK.put(index, uk2.toBytes());
        }
        return timeAttUK;
    }

    public void updateCtByTimeAttsUk(Ciphertext ct, Map<Integer, byte[]> uk_x) {
        for (Map.Entry<Integer, byte[]> entry : uk_x.entrySet()) {
            Element c4x = pairing.getG1().newElementFromBytes(ct.getC4(entry.getKey()));
            Element ukx = pairing.getG1().newElementFromBytes(entry.getValue());
            c4x.mul(ukx);
            ct.setC4(c4x.toBytes(), entry.getKey());
        }
    }

    public void setupGenLSSSUK() {
        //Authorities Setup
        String authoritys[] = new String[10];
        AuthorityKey authorityKeys[] = new AuthorityKey[10];
        String attributes[][] = new String[10][4];

        for (int i = 0; i < 10; i++) {
            authoritys[i] = "authority" + (i + 1);
            for (int j = 0; j < 4; j++) {
                int num = i * 4 + j;
                attributes[i][j] = "" + num;
            }
            authorityKeys[i] = EdgeTimeCPAbeV2.authoritySetup(authoritys[i], GP, attributes[i]);
        }

        //Generate UserKey
        String user1ID = "user1";
        CertUid certUid = EdgeTimeCPAbeV2.userRegistry(GP, user1ID);

        Message m = EdgeTimeCPAbeV2.generateRandomMessage(GP);
        System.out.println("原来的内容是：" + Arrays.toString(m.m) + "\n长度为：" + m.m.length);

        String oldPolicy = "and and and and and 0 0 and 1t 1t and and 2 2 and 3t 3t and and and 4 4 and 5t 5t and and 6 6 and 7t 7t and and and and 12 12 and 13t 13t and and 14 14 and 15t 15t and and and 16 16 and 17t 17t and and 18 18 and 19t 19t \n";
//        String newPolic2="and and and and and and 0 0 and 0 0 and and 1t 1t and 1t 1t and and and 2t 2t and 2t 2t and and 3 3 and 3 3 and and and and 12 12 and 12 12 and and 13t 13t and 13t 13t and and and 14t 14t and 14t 14t and and 15 15 and 15 15 and and and 8 9 and 10t 11t and and 20 21 and 22t 23t \n";
        String newPolicy = "and and and and and and 2t 2t and 2t 2t and and 3 3 and 3 3 and and and 12 12 and 12 12 and and 13t 13t and 13t 13t and and and and 14t 14t and 14t 14t and and 15 15 and 15 15 and and and 8 9 and 10t 11t and and 20 21 and 22t 23t and and and 0 0 and 0 0 and and 1t 1t and 1t 1t \n";
        AccessStructure oldArho = AccessStructure.buildFromPolicy(oldPolicy);
//        for (int i = 0; i <oldArho.getN() ; i++) {
//            System.out.println("旧访问策略第"+i+"行="+oldArho.rho(i).getAttribute());
//        }

        String fID = EdgeTimeCPAbeV2.generateRandomFid();
        Date begin = new Date(System.currentTimeMillis() - 100000);
        Date end = new Date(System.currentTimeMillis() + 100000);
        EncParam encParam1 = EdgeTimeCPAbeV2.genEncParam(GP, fID, begin, end, authoritys[0], "1", "3");
        EncParam encParam2 = EdgeTimeCPAbeV2.genEncParam(GP, fID, begin, end, authoritys[1], "5", "7");
        EncParam encParam3 = EdgeTimeCPAbeV2.genEncParam(GP, fID, begin, end, authoritys[3], "13", "15");
        EncParam encParam4 = EdgeTimeCPAbeV2.genEncParam(GP, fID, begin, end, authoritys[4], "17", "19");
        List<EncParam> encParams = new ArrayList<>();
        encParams.add(encParam1);
        encParams.add(encParam2);
        encParams.add(encParam3);
        encParams.add(encParam4);

        Map<String, byte[]> aaFidTPs = new HashMap<>();
        Map<String, byte[]> encryptParams = extractEncParam(encParams, aaFidTPs);
        EncInfo encInfo = new EncInfo();
        Ciphertext oldCt = timeEncrypt(m, fID, oldArho, encryptParams, encInfo);

        AccessStructure newArho = AccessStructure.buildFromPolicy(newPolicy);

        Map<Integer, AttNode> attList = new LinkedHashMap<>();
        List<List<String>> aaLists = new ArrayList<>();
        genAttAAMaps(attList, aaLists);
        Ciphertext newCt = updateCT(oldCt, attList, aaLists, encInfo, newArho, aaFidTPs);

        /*UserAuthorityKey uAK1 = EdgeTimeCPAbeV2.userAuthKeyGen(GP,authorityKeys[0].getAuthorityID(),authorityKeys[0].getSecretKey(),certUid,"0","2","4","6");


        TimeKey ctTimeKey1=EdgeTimeCPAbeV2.timeKeysGen(encParam1.getfID(),certUid,encParam1.getAaEncParam(),authorityKeys[0].getSecretKey(),GP,"1","3","5","7");

        uAK1.getUserTimeKeys().put(fID,ctTimeKey1);
        List<UserAuthorityKey>uAKS=new ArrayList<>();
        uAKS.add(uAK1);

        Userkeys userkeys=EdgeTimeCPAbeV2.keysGen(uAKS,user1ID,fID,certUid,GP);
        Message decM= EdgeTimeCPAbeV2.decrypt(ct,userkeys,GP);
        System.out.println("解密后明文为："+Arrays.toString(decM.m)+"\n长度为："+decM.m.length);*/

    }

    public void genAttAAMaps(Map<Integer, AttNode> s, List<List<String>> aaLists) {
        String oldPolicy = "and and and and and 0 0 and 1t 1t and and 2 2 and 3t 3t and and and 4 4 and 5t 5t and and 6 6 and 7t 7t and and and and 12 12 and 13t 13t and and 14 14 and 15t 15t and and and 16 16 and 17t 17t and and 18 18 and 19t 19t \n";
        String newPolicy = "and and and and and and 0 0 and 0 0 and and 1t 1t and 1t 1t and and and 2t 2t and 2t 2t and and 3 3 and 3 3 and and and and 12 12 and 12 12 and and 13t 13t and 13t 13t and and and 14t 14t and 14t 14t and and 15 15 and 15 15 and and and 8 9 and 10t 11t and and 20 21 and 22t 23t \n";
        //" 0 0 1t 1t  2 2  3t 3t 4 4  5t 5t  6 6 7t 7t  12 12  13t 13t  14 14  15t 15t  16 16  17t 17t  18 18  19t 19t \n";
        //" 0 0  0 0  1t 1t  1t 1t  2t 2t  2t 2t  3 3  3 3  12 12  12 12 13t 13t  13t 13t  14t 14t 14t 14t  15 15 15 15 20 21 22t 23t 24 25  26t 27t \n";
        AttNode[] attNodes = new AttNode[40];
        attNodes[0] = new AttNode(0, 0);
        attNodes[1] = new AttNode(1, 0);
        attNodes[2] = new AttNode(0, 1);
        attNodes[3] = new AttNode(1, 1);
        attNodes[4] = new AttNode(2, 0);
        attNodes[5] = new AttNode(3, 0);
        attNodes[6] = new AttNode(2, 1);
        attNodes[7] = new AttNode(3, 1);
        attNodes[8] = new AttNode(4, 0);
        attNodes[9] = new AttNode(5, 0);
        attNodes[10] = new AttNode(4, 1);
        attNodes[11] = new AttNode(5, 1);
        attNodes[12] = new AttNode(6, 0);
        attNodes[13] = new AttNode(7, 0);
        attNodes[14] = new AttNode(6, 1);
        attNodes[15] = new AttNode(7, 1);
        attNodes[16] = new AttNode(16, 0);
        attNodes[17] = new AttNode(17, 0);
        attNodes[18] = new AttNode(16, 1);
        attNodes[19] = new AttNode(17, 1);
        attNodes[20] = new AttNode(18, 0);
        attNodes[21] = new AttNode(19, 0);
        attNodes[22] = new AttNode(18, 1);
        attNodes[23] = new AttNode(19, 1);
        attNodes[24] = new AttNode(20, 0);
        attNodes[25] = new AttNode(21, 0);
        attNodes[26] = new AttNode(20, 1);
        attNodes[27] = new AttNode(21, 1);
        attNodes[28] = new AttNode(22, 0);
        attNodes[29] = new AttNode(23, 0);
        attNodes[30] = new AttNode(22, 1);
        attNodes[31] = new AttNode(23, 1);
        attNodes[32] = new AttNode(0, 2);
        attNodes[33] = new AttNode(0, 2);
        attNodes[34] = new AttNode(0, 2);
        attNodes[35] = new AttNode(0, 2);
        attNodes[36] = new AttNode(0, 2);
        attNodes[37] = new AttNode(0, 2);
        attNodes[38] = new AttNode(0, 2);
        attNodes[39] = new AttNode(0, 2);
        for (int i = 0; i < 40; i++) {
            s.put(i, attNodes[i]);
        }
        List<String> delAAs = new ArrayList<>();
        List<String> addAAS = new ArrayList<>();
        delAAs.add("authority2");
        delAAs.add("authority5");
        addAAS.add("authority6");
        addAAS.add("authority7");
        aaLists.add(delAAs);
        aaLists.add(addAAS);
    }

    public Ciphertext updateCT(Ciphertext oldCt, Map<Integer, AttNode> attLists, List<List<String>> aaLists, EncInfo encInfo, AccessStructure newArho, Map<String, byte[]> aaFidTPs) {
        Ciphertext newCT = new Ciphertext(newArho.getN());
        Map<Integer, byte[]> attRxMap = encInfo.getTx();
        Map<Integer, byte[]> lambdaMap = encInfo.getLambdaParam();
        Map<Integer, byte[]> timeParamMap = encInfo.getTimeParam();
        System.out.println("ct Component size=" + attRxMap.size());

        List<Boolean> isTimes = encInfo.getIsTime();
        List<Element> v = new ArrayList<>(newArho.getL());
        Element s = pairing.getZr().newElementFromBytes(encInfo.getS()).getImmutable();
        v.add(s);

        for (int i = 1; i < newArho.getL(); i++) {
            v.add(pairing.getZr().newRandomElement().getImmutable());
        }
//        for (int i = 0; i <newArho.getN() ; i++) {
//            System.out.println("新访问策略第"+i+"行="+newArho.rho(i).getAttribute());
//        }

        for (Map.Entry<Integer, AttNode> entry : attLists.entrySet()) {
            System.out.println("newPolicy Index=" + entry.getKey());
            AttNode attNode = entry.getValue();
            int oldindex = attNode.getOldIndex();
            byte[] oldLambda = lambdaMap.get(oldindex);
            byte[] oldAttRx = attRxMap.get(oldindex);
            boolean isTime = isTimes.get(oldindex);
            AttributeInfo oldAttInfo, newAttInfo;
            if (isTime) {
                byte[] timeParam = timeParamMap.get(oldindex);
                oldAttInfo = new TimeAttributeInfo(oldindex, oldLambda, oldAttRx, true, timeParam);
            } else {
                oldAttInfo = new AttributeInfo(oldindex, oldLambda, oldAttRx, false);
            }

            int newIndex = entry.getKey();
            String attribute = newArho.rho(newIndex).getAttribute();
            String authority = GP.getAPKS().getTMap().get(attribute);
            Element newLambda = EdgeTimeCPAbeV2.dotProduct(newArho.getRow(newIndex), v, pairing.getZr().newZeroElement(), pairing).getImmutable();
            if (newArho.rho(newIndex).isTimeLimited()) {
                Element newTimeParam;
                if (aaFidTPs.containsKey(authority)) {
                    newTimeParam = pairing.getZr().newElementFromBytes(aaFidTPs.get(authority));
                    newAttInfo = new TimeAttributeInfo(newIndex, newLambda.toBytes(), oldAttRx, true, newTimeParam.toBytes());
                } else {
                    newTimeParam = pairing.getZr().newRandomElement();
                    newAttInfo = new TimeAttributeInfo(newIndex, newLambda.toBytes(), oldAttRx, true, newTimeParam.toBytes());
                    aaFidTPs.put(authority, newTimeParam.toBytes());
                }
            } else {
                newAttInfo = new AttributeInfo(newIndex, newLambda.toBytes(), oldAttRx, false);
            }
            System.out.println("attribute=" + attribute);
            LsssUKInfo lsssUKInfo = new LsssUKInfo(oldAttInfo, newAttInfo, GP.getAPKS().getAPKByAttr(attribute).getG1yi());
            //生成Case1的更新秘钥

            LsssCtAttUk lsssCtAttUk = null;
            switch (attNode.getType()) {
                case 0:
                    long t1 = System.nanoTime();
                    lsssCtAttUk = genLsssCtAttUkCase1(lsssUKInfo);
                    log.info("case 1 UkGen Time =" + (System.nanoTime() - t1) * 1.0 / 1000000 + " ms");
                    break;
                case 1:
                    long t2 = System.nanoTime();
                    lsssCtAttUk = genLsssCtAttUkCase2(lsssUKInfo);
                    log.info("case 2 UkGen Time =" + (System.nanoTime() - t2) * 1.0 / 1000000 + " ms");
                    break;
                case 2:
                    long t3 = System.nanoTime();
                    lsssCtAttUk = genLsssCtAttUkCase3(newAttInfo, lsssUKInfo.getaAPK2(), attribute);
                    log.info("case 3 UkGen Time =" + (System.nanoTime() - t3) * 1.0 / 1000000 + " ms");
                    break;
            }

            byte[] c2x = oldCt.getC2(oldindex);
            byte[] c3x = oldCt.getC3(oldindex);
            byte[] c4x = oldCt.getC4(oldindex);
            //执行密文更新算法
            UpdateCtComponent updateCtComponent = null;
            switch (attNode.getType()) {
                case 0:
                    long case1T = System.nanoTime();
                    updateCtComponent = cTComponentUpdateCase1(c2x, c4x, lsssCtAttUk);
                    log.info("case 1 CtUpdate Time =" + (System.nanoTime() - case1T) * 1.0 / 1000000 + " ms");
                    break;
                case 1:
                    long case2T = System.nanoTime();
                    updateCtComponent = cTComponentUpdateCase2(c2x, c3x, c4x, lsssCtAttUk);
                    log.info("case 2 CtUpdate Time =" + (System.nanoTime() - case2T) * 1.0 / 1000000 + " ms");
                    break;
                case 2:
                    long case3T = System.nanoTime();
                    updateCtComponent = cTComponentUpdateCase3(lsssCtAttUk);
                    log.info("case 3 CtUpdate Time =" + (System.nanoTime() - case3T) * 1.0 / 1000000 + " ms");
                    break;
            }
            log.info(" ");
            newCT.setC2(updateCtComponent.getC2x());
            newCT.setC4(updateCtComponent.getC4x());
            if (attNode.getType() == 0) {
                newCT.setC3(c3x);
            } else {
                newCT.setC3(updateCtComponent.getC3x());
            }
        }

        List<byte[]> delAAPks = new LinkedList<>();
        Map<String, AuthPublicKey> aaMap = GP.getAPKS().getaAPKMap();
        for (String delAA : aaLists.get(0)) {
            AuthPublicKey aaPk = aaMap.get(delAA);
            delAAPks.add(aaPk.getEg1g1ai());
        }
        List<byte[]> addAAPks = new LinkedList<>();
        for (String addAA : aaLists.get(1)) {
            AuthPublicKey aaPk = aaMap.get(addAA);
            addAAPks.add(aaPk.getEg1g1ai());
        }
        long t4 = System.nanoTime();
        LsssCtAttUk lsssCtAAUk = genLsssCtAttUkCase4(s.toBytes(), delAAPks, addAAPks);
        log.info("case 4 UkGen Time = " + (System.nanoTime() - t4) * 1.0 / 1000000 + " ms");

        byte[] c0 = oldCt.getC0();
        long case4T = System.nanoTime();
        byte[] newC0 = cTComponentUpdateCase4(c0, lsssCtAAUk);
        log.info("case 4 CtUpdate Time =" + (System.nanoTime() - case4T) * 1.0 / 1000000 + " ms");

        newCT.setC0(newC0);
        newCT.setC1(oldCt.getC0());
        newCT.setAccessStructure(newArho);
        Set<String> newAASets = new HashSet<>(oldCt.getAuthorities());
        newAASets.addAll(aaLists.get(1));
        newAASets.removeAll(aaLists.get(0));
        newCT.setAuthorities(newAASets);
        newCT.setfID(oldCt.getfID());
        return newCT;
    }

    public LsssCtAttUk genLsssCtAttUkCase1(LsssUKInfo lsssUKInfo) {
        AttributeInfo oldAtt = lsssUKInfo.getOldAtt();
        AttributeInfo newAtt = lsssUKInfo.getNewAtt();
        Element newLambda = pairing.getZr().newElementFromBytes(newAtt.getLambda());
        Element oldLambda = pairing.getZr().newElementFromBytes(oldAtt.getLambda());

        Element ga = pairing.getG1().newElementFromBytes(GP.getGa()).getImmutable();
        Element uk1 = ga.powZn(newLambda.sub(oldLambda));

        Element aAPk2 = pairing.getG1().newElementFromBytes(lsssUKInfo.getaAPK2()).getImmutable();

        Element uk2 = null;
        if (oldAtt.isTime() && !newAtt.isTime()) {
            log.info("case 1 type 2  oldAtt time ,newAtt normal");
            Element oldTimeParam = pairing.getZr().newElementFromBytes(((TimeAttributeInfo) oldAtt).getTimeParam());
            Element attParam = pairing.getZr().newElementFromBytes(oldAtt.getAttRx()).getImmutable();
            uk2 = aAPk2.powZn(attParam.sub(attParam.mul(oldTimeParam)));
        } else if (!oldAtt.isTime() && newAtt.isTime()) {
            log.info("case1 type 3 oldAtt normal ,newAtt time");
            Element oldAttParam = pairing.getZr().newElementFromBytes(oldAtt.getAttRx()).getImmutable();
            Element newTimeParam = pairing.getZr().newElementFromBytes(((TimeAttributeInfo) newAtt).getTimeParam());
            uk2 = aAPk2.powZn(oldAttParam.mul(newTimeParam).sub(oldAttParam));
        } else {
            log.info("case 1 type 1 oldAtt and newAtt are same ");
            uk2 = pairing.getG1().newOneElement();
        }

        LsssCtAttUk lsssCtAttUk = new LsssCtAttUk(uk1.toBytes(), uk2.toBytes());
        return lsssCtAttUk;
    }

    public LsssCtAttUk genLsssCtAttUkCase2(LsssUKInfo lsssUKInfo) {
        AttributeInfo oldAtt = lsssUKInfo.getOldAtt();
        AttributeInfo newAtt = lsssUKInfo.getNewAtt();
        Element newLambda = pairing.getZr().newElementFromBytes(newAtt.getLambda());
        Element oldLambda = pairing.getZr().newElementFromBytes(oldAtt.getLambda());
        Element vx = pairing.getZr().newRandomElement().getImmutable();

        Element ga = pairing.getG1().newElementFromBytes(GP.getGa()).getImmutable();
        Element uk1 = ga.powZn(newLambda.sub(vx.mul(oldLambda)));

        Element aAPk2 = pairing.getG1().newElementFromBytes(lsssUKInfo.getaAPK2()).getImmutable();
        Element oldAttParam = pairing.getZr().newElementFromBytes(oldAtt.getAttRx()).getImmutable();
        Element temp = oldAttParam.mul(vx).getImmutable();
        Element uk2 = null;
        if (oldAtt.isTime() && !newAtt.isTime()) {
            log.info("case 2 type 2 oldAtt time ,newAtt normal");
            Element oldTimeParam = pairing.getZr().newElementFromBytes(((TimeAttributeInfo) oldAtt).getTimeParam());
            uk2 = aAPk2.powZn(temp.sub(temp.mul(oldTimeParam)));
        } else if (!oldAtt.isTime() && newAtt.isTime()) {
            log.info("case 2 type 3 oldAtt normal ,newAtt time");
            Element newTimeParam = pairing.getZr().newElementFromBytes(((TimeAttributeInfo) newAtt).getTimeParam());
            uk2 = aAPk2.powZn(temp.mul(newTimeParam).sub(temp));
        } else {
            log.info("case 2 type 1 oldAtt and newAtt are same ");
            uk2 = pairing.getG1().newOneElement();
        }
        LsssCtAttUk lsssCtAttUk = new LsssCtAttUkCase2(uk1.toBytes(), uk2.toBytes(), vx.toBytes());
        return lsssCtAttUk;
    }

    public LsssCtAttUk genLsssCtAttUkCase3(AttributeInfo newAtt, byte[] aAPK, String attribute) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element newLambda = pairing.getZr().newElementFromBytes(newAtt.getLambda());

        Element ga = pairing.getG1().newElementFromBytes(GP.getGa()).getImmutable();
        Element aAPk2 = pairing.getG1().newElementFromBytes(aAPK).getImmutable();
        Element attRx = pairing.getZr().newRandomElement().getImmutable();
        Element uk1 = ga.powZn(newLambda).mul(aAPk2.powZn(attRx));

        Element fAtt = pairing.getG1().newElementFromBytes(attribute.getBytes()).getImmutable();
        Element uk2 = null;
        if (newAtt.isTime()) {
            log.info("case 3 type 2 newAtt is  time");
            Element newTimeParam = pairing.getZr().newElementFromBytes(((TimeAttributeInfo) newAtt).getTimeParam());
            uk2 = aAPk2.powZn(attRx.mul(newTimeParam)).mul(fAtt.powZn(attRx));
        } else {
            log.info("case 3 type 1 newAtt is normal");
            uk2 = aAPk2.powZn(attRx).mul(fAtt.powZn(attRx));
        }
        Element g = pairing.getG1().newElementFromBytes(GP.getG());
        Element uk3 = g.powZn(attRx.negate());
        LsssCtAttUk lsssCtAttUk = new LsssCtAttUkCase3(uk1.toBytes(), uk2.toBytes(), uk3.toBytes());
        return lsssCtAttUk;
    }

    public LsssCtAttUk genLsssCtAttUkCase4(byte[] sb, List<byte[]> delAAS, List<byte[]> addAAS) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element s = pairing.getZr().newElementFromBytes(sb).getImmutable();
        Element uk1 = pairing.getGT().newOneElement();
        for (byte[] delAA : delAAS) {
            Element aAPK1 = pairing.getGT().newElementFromBytes(delAA);
            uk1.mul(aAPK1);
        }
        uk1.powZn(s.negate());

        Element uk2 = pairing.getGT().newOneElement();
        for (byte[] addAA : addAAS) {
            Element aAPK1 = pairing.getGT().newElementFromBytes(addAA);
            uk2.mul(aAPK1);
        }
        uk2.powZn(s);

        LsssCtAttUk lsssCtAttUk = new LsssCtAttUk(uk1.toBytes(), uk2.toBytes());
        return lsssCtAttUk;
    }

    public UpdateCtComponent cTComponentUpdateCase1(byte[] c2x, byte[] c4x, LsssCtAttUk lsssCtAttUk) {
        Element c2xx = pairing.getG1().newElementFromBytes(c2x);
        Element uk1 = pairing.getG1().newElementFromBytes(lsssCtAttUk.getUk1());
        c2xx.mul(uk1);

        Element c4xx = pairing.getG1().newElementFromBytes(c4x);
        Element uk2 = pairing.getG1().newElementFromBytes(lsssCtAttUk.getUk2());
        c4xx.mul(uk2);

        return new UpdateCtComponent(c2xx.toBytes(), c4xx.toBytes());

    }

    public UpdateCtComponent cTComponentUpdateCase2(byte[] c2x, byte[] c3x, byte[] c4x, LsssCtAttUk lsssCtAttUk) {
        Element c2xx = pairing.getG1().newElementFromBytes(c2x);
        Element uk1 = pairing.getG1().newElementFromBytes(lsssCtAttUk.getUk1());
        Element vx = pairing.getZr().newElementFromBytes(((LsssCtAttUkCase2) lsssCtAttUk).getVx()).getImmutable();
        c2xx.powZn(vx).mul(uk1);

        Element c3xx = pairing.getG1().newElementFromBytes(c3x);
        c3xx.powZn(vx);

        Element c4xx = pairing.getG1().newElementFromBytes(c4x);
        Element uk2 = pairing.getG1().newElementFromBytes(lsssCtAttUk.getUk2());
        c4xx.powZn(vx).mul(uk2);

        UpdateCtComponent updateCtComponent = new UpdateCtComponent(c2xx.toBytes(), c4xx.toBytes());
        updateCtComponent.setC3x(c3xx.toBytes());
        return updateCtComponent;
    }

    public UpdateCtComponent cTComponentUpdateCase3(LsssCtAttUk lsssCtAttUk) {
        UpdateCtComponent updateCtComponent = new UpdateCtComponent(lsssCtAttUk.getUk1(), lsssCtAttUk.getUk2());
        updateCtComponent.setC3x(((LsssCtAttUkCase3) lsssCtAttUk).getUk3());
        return updateCtComponent;
    }

    public byte[] cTComponentUpdateCase4(byte[] C0, LsssCtAttUk lsssCtAttUk) {
        Element c0 = pairing.getGT().newElementFromBytes(C0);
        Element uk1 = pairing.getGT().newElementFromBytes(lsssCtAttUk.getUk1());
        Element uk2 = pairing.getGT().newElementFromBytes(lsssCtAttUk.getUk2());
        c0.mul(uk1).mul(uk2);
        return c0.toBytes();
    }


    public static void main(String[] args) {
        int Lambda = 512;
        GlobalParam gp = EdgeTimeCPAbeV2.globalSetup(Lambda);
        PolicyCompare policyCompare = new PolicyCompare(gp);
        for (int i = 0; i < 10; i++) {
            policyCompare.setupGenTimeAttUK(4, 8, 1, 4);
        }
//        policyCompare.setupGenLSSSUK();
//        byte[] a={59, 50, 59, -50, -113, 109, 72, 7, -102, 112, -7, -18, -101, -30, 98, -100, 62, 78, -22, 88, 32, -104, 97, -57, 75, -100, 55, -11, 2, 24, 80, 36, 111, -61, -12, 87, -90, -31, 62, 51, -9, 95, 78, -124, -61};
    }
}
