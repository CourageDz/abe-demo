package com.dzy.abedemo.cpabe.util;

import com.dzy.abedemo.cpabe.authority.AuthPublicKey;
import com.dzy.abedemo.cpabe.authority.AuthSecretKey;
import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.authority.AuthorityPublicKeys;
import com.dzy.abedemo.cpabe.ciphertext.*;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.timeParam.AAEncParam;
import com.dzy.abedemo.cpabe.timeParam.EncParam;
import com.dzy.abedemo.cpabe.timeParam.TimeAttKey;
import com.dzy.abedemo.cpabe.timeParam.TimeKey;
import com.dzy.abedemo.cpabe.userKey.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

public class EdgeTimeCPAbeV2 {
    private static Logger log = LoggerFactory.getLogger(EdgeTimeCPAbeV2.class);

    //write Pojo to file
    public static void writeJavaPojoToFile(Object object, String filePath, String fileName) {
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filePath + "/" + fileName));
            out.writeObject(object);
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static Object readJavaPojoFromFile(Class clazz, String filePath, String fileName) throws Exception {
        Object object = Class.forName(clazz.getName()).newInstance();
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream(filePath + "/" + fileName));
            object = in.readObject();
            in.close();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return object;
    }

    //first counstructed base CPABE
    public static GlobalParam globalSetup(int lambda) {
        //官方文档中rbits=160,lambda=512
        GlobalParam params = new GlobalParam();

        params.setPairingParameters(new TypeACurveGenerator(160, lambda).generate());//rbits 是Zp中阶数p的位数  ，qbits G中阶数的位数
        Pairing pairing = PairingFactory.getPairing(params.getPairingParameters());

        Element g = pairing.getG1().newRandomElement().getImmutable();
        params.setG(g.toBytes());
        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element ga = g.powZn(a);
        params.setGa(ga.toBytes());
        return params;
    }

    public static CertUid userRegistry(GlobalParam GP, String userID) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element uJ = pairing.getZr().newRandomElement().getImmutable();
        CertUid certUid = new CertUid(userID);
        certUid.setuUid(uJ.toBytes());
        return certUid;
    }

    public static AuthorityKey authoritySetup(String authorityID, GlobalParam GP, String... attributes) {

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        AuthorityPublicKeys APKS = GP.getAPKS();
        Element g = pairing.getG1().newElementFromBytes(GP.getG()).getImmutable();
        Element egg = pairing.pairing(g, g);
        Element ad = pairing.getZr().newRandomElement().getImmutable();
        Element yd = pairing.getZr().newRandomElement().getImmutable();

        Element egg_ad = egg.powZn(ad);
        Element g_yd = g.powZn(yd);


        AuthPublicKey authPublicKey = new AuthPublicKey(egg_ad.toBytes(), g_yd.toBytes());
        AuthSecretKey authSecretKey = new AuthSecretKey(ad.toBytes(), yd.toBytes());
        AuthorityKey authorityKeys = new AuthorityKey(authorityID);
        authorityKeys.setPublicKey(authPublicKey);
        authorityKeys.setSecretKey(authSecretKey);

        for (String attribute : attributes) {
            APKS.getTMap().put(attribute, authorityID);
        }
        APKS.getaAPKMap().put(authorityID, authPublicKey);

        return authorityKeys;
    }

    //gen [ti tj] encParam in fid
    public static EncParam genEncParam(GlobalParam GP, String fID, Date begin, Date end, String authority, String... attributes) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        EncParam encParam = new EncParam(fID);
        AAEncParam aaEncParam = encParam.getAaEncParam();
        aaEncParam.setAuthority(authority);
        Element r = pairing.getZr().newElementFromBytes((fID + begin.toString() + end.toString()).getBytes()).getImmutable();
        Element g = pairing.getG1().newElementFromBytes(GP.getG());
        encParam.setParam(r.toBytes());
        Element gr = g.powZn(r);
        aaEncParam.setEncParam(gr.toBytes());
        aaEncParam.setBegin(begin);
        aaEncParam.setEnd(end);
        aaEncParam.addAttribtue(attributes);
        return encParam;
    }

    //从中提取出加密需要的指数
    public static Map<String, byte[]> extractEncParam(List<EncParam> encParams) {
        Map<String, byte[]> timeAttributes = new HashMap<>();
        for (EncParam encParam : encParams) {
            for (String attribute : encParam.getAaEncParam().getAttributes()) {
                timeAttributes.put(attribute, encParam.getParam());
            }
        }
        return timeAttributes;
    }

    public static Ciphertext timeEncrypt(Message message, String fID, AccessStructure arho, GlobalParam GP, Map<String, byte[]> timeAttributes) {
        Ciphertext ct = new Ciphertext();
        ct.setfID(fID);
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
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

        Set<String> authorities = ct.getAuthorities();
        for (int i = 0; i < arho.getN(); i++) {
            Element lambdaX = dotProduct(arho.getRow(i), v, pairing.getZr().newZeroElement(), pairing).getImmutable();

            Element rx = pairing.getZr().newRandomElement().getImmutable();

            boolean isTimeLimited = arho.rho(i).isTimeLimited();
            String attribute = arho.rho(i).getAttribute();
            String authorityID = AKS.getTMap().get(attribute);
            if (!authorities.contains(authorityID)) {
                authorities.add(authorityID);
                Element eggAi = pairing.getGT().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getEg1g1ai());
                c0.mul(eggAi);
            }

            Element gYi = pairing.getG1().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getG1yi()).getImmutable();
            Element attG1 = pairing.getG1().newElementFromBytes(attribute.getBytes()).getImmutable();

            ct.setC2(gA.powZn(lambdaX).mul(gYi.powZn(rx)).toBytes());

            Element c3x = g.powZn(rx.negate());
            ct.setC3(c3x.toBytes());

            if (isTimeLimited) {
                Element tx = pairing.getZr().newElementFromBytes(timeAttributes.get(attribute));
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

    public static Ciphertext normalEncrypt(Message message, AccessStructure arho, GlobalParam GP) {

        Ciphertext ct = new Ciphertext();
        String fID = generateRandomFid();
        ct.setfID(fID);
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
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

        Set<String> authorities = ct.getAuthorities();
        for (int i = 0; i < arho.getN(); i++) {

            Element lambdaX = dotProduct(arho.getRow(i), v, pairing.getZr().newZeroElement(), pairing).getImmutable();

            Element rx = pairing.getZr().newRandomElement().getImmutable();
            String attribute = arho.rho(i).getAttribute();
            String authorityID = AKS.getTMap().get(attribute);
            if (!authorities.contains(authorityID)) {
                authorities.add(authorityID);
                Element eggAi = pairing.getGT().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getEg1g1ai());
                c0.mul(eggAi);
            }

            Element gYi = pairing.getG1().newElementFromBytes(AKS.getaAPKMap().get(authorityID).getG1yi()).getImmutable();

            Element attG1 = pairing.getG1().newElementFromBytes(attribute.getBytes());
//            Element attG1= HashFunction.hashToG1(pairing,attribute.getBytes());

            ct.setC2(gA.powZn(lambdaX).mul(gYi.powZn(rx)).toBytes());

            Element c3x = g.powZn(rx.negate());
            ct.setC3(c3x.toBytes());

            ct.setC4(attG1.powZn(rx).mul(gYi.powZn(rx)).toBytes());

        }
        /*for(String authority: authorities){
            Element eggAi = pairing.getGT().newElementFromBytes(AKS.getaAPKMap().get(authority).getEg1g1ai());
            c0.mul(eggAi);
        }*/
        ct.setC0(M.mul(c0.powZn(s)).toBytes());
        return ct;
    }

    //生成用户的各个授权机构的秘钥
    public static UserAuthorityKey userAuthKeyGen(GlobalParam GP, String authority, AuthSecretKey sk, CertUid certUid, String... attributes) {

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element g = pairing.getG1().newElementFromBytes(GP.getG()).getImmutable();

        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element u = pairing.getZr().newElementFromBytes(certUid.getuUid()).getImmutable();
        Element ai = pairing.getZr().newElementFromBytes(sk.getAi()).getImmutable();
        Element yi = pairing.getZr().newElementFromBytes(sk.getYi()).getImmutable();
        Element ga = pairing.getG1().newElementFromBytes(GP.getGa()).getImmutable();

        UserAuthorityKey uAKey = new UserAuthorityKey(authority);

        Element kjk = g.powZn(ai).mul(ga.powZn(u));
        uAKey.setKjk(kjk.toBytes());

        Element ljk = g.powZn(t);
        uAKey.setLjk(ljk.toBytes());
        //未考虑重复属性的情况
        for (String attribute : attributes) {
            UserAttributeKey attKey = new UserAttributeKey(attribute);
            Element attG1 = pairing.getG1().newElementFromBytes(attribute.getBytes()).getImmutable();
            Element kj_xk = g.powZn(yi.mul(t.add(u))).mul(attG1.powZn(t));
            attKey.setKj_xk(kj_xk.toBytes());
            uAKey.getUserAttKeys().put(attribute, attKey);
        }
        return uAKey;
    }

    //生成用户在该授权机构下的属性的时间秘钥，并将其添加到用户的授权机构秘钥中
    public static TimeKey timeKeysGen(String fID, CertUid certUid, AAEncParam aaEncParam, AuthSecretKey ASK, GlobalParam GP, String... attributes) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element g = pairing.getG1().newElementFromBytes(GP.getG()).getImmutable();
        Date now = new Date();
        Element gTx = pairing.getG1().newElement();
//        SimpleDateFormat ft = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
        if ((now.compareTo(aaEncParam.getBegin())) >= 0 && (now.compareTo(aaEncParam.getEnd())) <= 0) {
            gTx.setFromBytes(aaEncParam.getEncParam());
            gTx = gTx.getImmutable();
        } else
            throw new IllegalArgumentException("illegality time");

        Element yi = pairing.getZr().newElementFromBytes(ASK.getYi()).getImmutable();
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element uj = pairing.getZr().newElementFromBytes(certUid.getuUid()).getImmutable();

        TimeKey timeKey = new TimeKey(fID, aaEncParam.getAuthority());

        Element ljk = g.powZn(t);
        timeKey.setLjk(ljk.toBytes());
        for (String attribute : attributes) {
            Element fAtt = pairing.getG1().newElementFromBytes(attribute.getBytes()).getImmutable();
            Element tkj_xk = gTx.powZn(yi.mul(t)).mul(g.powZn(uj.mul(yi)).mul(fAtt.powZn(t)));
            timeKey.addUserAttribute(attribute, tkj_xk.toBytes());
        }
        return timeKey;
    }

    public static Userkeys keysGen(List<UserAuthorityKey> userAKeys, String userID, CertUid certUid, GlobalParam GP) {
        Userkeys userkeys = new Userkeys(userID);
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element uj = pairing.getZr().newElementFromBytes(certUid.getuUid());
        Element g = pairing.getG1().newElementFromBytes(GP.getG());
        Element rj = g.powZn(uj);
        userkeys.setRj(rj.toBytes());
        for (UserAuthorityKey uAK : userAKeys) {
            userkeys.getUserAuthKeys().put(uAK.getAuthority(), uAK);
            userkeys.addAttributes(uAK.getAttributes());
        }
        return userkeys;
    }

    public static Userkeys keysGen(List<UserAuthorityKey> userAKeys, String userID, String fID, CertUid certUid, GlobalParam GP) {
        Userkeys userkeys = new Userkeys(userID);
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element uj = pairing.getZr().newElementFromBytes(certUid.getuUid());
        Element g = pairing.getG1().newElementFromBytes(GP.getG());
        Element rj = g.powZn(uj);
        userkeys.setRj(rj.toBytes());
        for (UserAuthorityKey uAK : userAKeys) {
            userkeys.getUserAuthKeys().put(uAK.getAuthority(), uAK);
            userkeys.addAttributes(uAK.getAttributes());
            if (uAK.getUserTimeKeys().size() != 0) {
                userkeys.addAttributes(uAK.getTimeAttributes(fID));
            }
        }
        return userkeys;
    }

    public static UserSplitKeys edgeKeysGen(Userkeys userkeys, GlobalParam GP, String... fID) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        UserSplitKeys usk = new UserSplitKeys(userkeys.getUserID());
        EdgeKeys edgeKeys = usk.getEdgeKeys();
        edgeKeys.setAttributes(userkeys.getAttributes());
        Element z = pairing.getZr().newRandomElement().getImmutable();

        for (UserAuthorityKey uAK : userkeys.getUserAuthKeys().values()) {
            Element kjk = pairing.getG1().newElementFromBytes(uAK.getKjk());
            kjk.powZn(z.invert());

            Element ljk = pairing.getG1().newElementFromBytes(uAK.getLjk());
            ljk.powZn(z.invert());
            EdgeUserAuthKey edgeUAK = new EdgeUserAuthKey(kjk.toBytes(), ljk.toBytes());
            //添加授权机构秘钥
            edgeKeys.addEdgeUserAuthKey(uAK.getAuthority(), edgeUAK);
            //添加普通属性秘钥
            for (UserAttributeKey uAttKey : uAK.getUserAttKeys().values()) {
                String attribute = uAttKey.getAttribute();
//                if(uAK.getTimeAttributes(fID).contains(attribute))
//                    continue;
                Element kj_xk = pairing.getG1().newElementFromBytes(uAttKey.getKj_xk());
                kj_xk.powZn(z.invert());
                edgeKeys.addAttributeKey(attribute, kj_xk.toBytes());
            }
            //添加时间属性秘钥
            for (TimeKey timeKey : uAK.getUserTimeKeys().values()) {
                Element ljk2 = pairing.getG1().newElementFromBytes(timeKey.getLjk());
                ljk2.powZn(z.invert());
                for (Map.Entry<String, byte[]> attEntry : timeKey.getUserAttKeys().entrySet()) {
                    Element kj_xk = pairing.getG1().newElementFromBytes(attEntry.getValue());
                    kj_xk.powZn(z.invert());
                    TimeAttKey timeAttKey = new TimeAttKey(kj_xk.toBytes(), ljk2.toBytes());
                    edgeKeys.addTimeAttKey(attEntry.getKey(), timeAttKey);
                }
            }
        }
        Element rJ = pairing.getG1().newElementFromBytes(userkeys.getRj());
        rJ.powZn(z.invert());
        edgeKeys.setRj(rJ.toBytes());
        usk.setZ(z.toBytes());
        return usk;
    }

    public static Message decrypt(Ciphertext CT, Userkeys userkeys, GlobalParam GP) {
        List<Integer> toUse = CT.getAccessStructure().getIndexesList(userkeys.getAttributes());

        if (null == toUse || toUse.isEmpty()) throw new IllegalArgumentException("not satisfied");

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element t = pairing.getGT().newOneElement();

        Element rj = pairing.getG1().newElementFromBytes(userkeys.getRj()).getImmutable();
        //可以优化，将每个授权机构的属性分离出来
        for (Integer x : toUse) {

            AttElement attElement = CT.getAccessStructure().rho(x);
            String attribute = attElement.getAttribute();
            boolean isTimeLimited = attElement.isTimeLimited();
//            log.info("attributes in dec:="+attribute);
            String authorityID = GP.getAPKS().getTMap().get(attribute);
            Element c2x = pairing.getG1().newElementFromBytes(CT.getC2(x));
            Element p2 = pairing.pairing(c2x, rj);


            Element kj_xk = pairing.getG1().newElement();
            Element ljk = pairing.getG1().newElement();
            if (isTimeLimited) {
                kj_xk = pairing.getG1().newElementFromBytes(userkeys.getUserAuthKeys().get(authorityID).getUserTimeKeys().get(CT.getfID()).getUserAttKeys().get(attribute));
                ljk = pairing.getG1().newElementFromBytes(userkeys.getUserAuthKeys().get(authorityID).getUserTimeKeys().get(CT.getfID()).getLjk());
            } else {
                kj_xk = pairing.getG1().newElementFromBytes(userkeys.getUserAuthKeys().get(authorityID).getUserAttKeys().get(attribute).getKj_xk());
                ljk = pairing.getG1().newElementFromBytes(userkeys.getUserAuthKeys().get(authorityID).getLjk());
            }
            Element c3x = pairing.getG1().newElementFromBytes(CT.getC3(x));
            Element p3 = pairing.pairing(kj_xk, c3x);

            Element c4x = pairing.getG1().newElementFromBytes(CT.getC4(x));
            Element p4 = pairing.pairing(ljk, c4x);

            t.mul(p2.mul(p3).mul(p4));
        }
        int nA = CT.getAuthorities().size();
        log.info("NA in dec:=" + nA);
        Element NA = pairing.getZr().newElement(nA);

        t.powZn(NA);
        t.invert();
        Element c1x = pairing.getG1().newElementFromBytes(CT.getC1());

        for (String authority : CT.getAuthorities()) {
            Element kjk = pairing.getG1().newElementFromBytes(userkeys.getUserAuthKeys().get(authority).getKjk());
            Element p1 = pairing.pairing(c1x, kjk);

            t.mul(p1);
        }
        Element c0 = pairing.getGT().newElementFromBytes(CT.getC0());
        c0.mul(t.invert());
        return new Message(c0.toBytes());

    }

    public static LocaleCiphertext outsourceDecrypt(Ciphertext CT, EdgeKeys edgeKeys, GlobalParam GP) {
        List<Integer> toUse = CT.getAccessStructure().getIndexesList(edgeKeys.getAttributes());

        if (null == toUse || toUse.isEmpty()) throw new IllegalArgumentException("not satisfied");

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element t = pairing.getGT().newOneElement();

        Element rj = pairing.getG1().newElementFromBytes(edgeKeys.getRj()).getImmutable();
        //可以优化，将每个授权机构的属性分离出来
        for (Integer x : toUse) {

            AttElement attElement = CT.getAccessStructure().rho(x);
            String attribute = attElement.getAttribute();
            boolean isTimeLimited = attElement.isTimeLimited();
//            log.info("attributes in dec:="+attribute);
            String authorityID = GP.getAPKS().getTMap().get(attribute);
            Element c2x = pairing.getG1().newElementFromBytes(CT.getC2(x));
            Element p2 = pairing.pairing(c2x, rj);


            Element kj_xk = pairing.getG1().newElement();
            Element ljk = pairing.getG1().newElement();
            if (isTimeLimited) {
//                System.out.println("Time attribute :"+attribute);
                kj_xk = pairing.getG1().newElementFromBytes(edgeKeys.getTimeAttKey(attribute).getKj_xk());
                ljk = pairing.getG1().newElementFromBytes(edgeKeys.getTimeAttKey(attribute).getLj_xk());
            } else {
                kj_xk = pairing.getG1().newElementFromBytes(edgeKeys.getAttributeKey(attribute));
                ljk = pairing.getG1().newElementFromBytes(edgeKeys.getEdgeUserAuthKey(authorityID).getLjk());
            }
            Element c3x = pairing.getG1().newElementFromBytes(CT.getC3(x));
            Element p3 = pairing.pairing(kj_xk, c3x);

            Element c4x = pairing.getG1().newElementFromBytes(CT.getC4(x));
            Element p4 = pairing.pairing(ljk, c4x);

            t.mul(p2.mul(p3).mul(p4));
        }
        int nA = CT.getAuthorities().size();
        log.info("NA in dec:=" + nA);
        Element NA = pairing.getZr().newElement(nA);

        t.powZn(NA);
        t.invert();
        Element c1x = pairing.getG1().newElementFromBytes(CT.getC1());

        for (String authority : CT.getAuthorities()) {
            Element kjk = pairing.getG1().newElementFromBytes(edgeKeys.getEdgeUserAuthKey(authority).getKjk());
            Element p1 = pairing.pairing(c1x, kjk);

            t.mul(p1);
        }
        LocaleCiphertext LC = new LocaleCiphertext();
        LC.setC0(CT.getC0());
        LC.setC1(t.toBytes());
        return LC;
    }

    public static Message localDecrypt(LocaleCiphertext LC, byte[] usk, GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element z = pairing.getZr().newElementFromBytes(usk).getImmutable();

        Element c0 = pairing.getGT().newElement();
        c0.setFromBytes(LC.getC0());

        Element c1 = pairing.getGT().newElementFromBytes(LC.getC1());
        c1.powZn(z);
        c0.mul(c1.invert());
        return new Message(c0.toBytes());
    }

    public static Element dotProduct(List<AccessStructure.MatrixElement> v1, List<Element> v2, Element element, Pairing pairing) {
        if (v1.size() != v2.size()) throw new IllegalArgumentException("different length in acess policy");
        if (element.isImmutable()) throw new IllegalArgumentException("result is immutable");

        if (!element.isZero()) {
            element.setToZero();
        }

        for (int i = 0; i < v1.size(); i++) {
            Element e = pairing.getZr().newElement();
            switch (v1.get(i)) {
                case MINUS_ONE:
                    e.setToOne().negate();
                    break;
                case ONE:
                    e.setToOne();
                    break;
                case ZERO:
                    e.setToZero();
                    break;
            }
            element.add(e.mul(v2.get(i).getImmutable()));
        }
        return element;
    }

    public static Message generateRandomMessage(GlobalParam GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element M = pairing.getGT().newRandomElement().getImmutable();
        return new Message(M.toBytes());
    }

    public static String generateRandomFid() {
        long time = System.currentTimeMillis();
        long randomNum = time % 100000000;
        String fID = String.valueOf(randomNum);
        return fID;
    }

    public static void main(String[] args) throws Exception {
        GlobalParam gp = EdgeTimeCPAbeV2.globalSetup(512);
        Pairing oldPairing = PairingFactory.getPairing(gp.getPairingParameters());
        Element oldGa = oldPairing.getG1().newElementFromBytes(gp.getGa());
        gp.getAPKS().getTMap().put("A", "1");
        System.out.println("origanal ga:=" + oldGa);
        System.out.println("orginal A:=" + gp.getAPKS().getTMap().get("A"));
        String filePath = "F://edgeCPAbe";
        String fileName = "GlobalParam.dat";
        writeJavaPojoToFile(gp, filePath, fileName);
        GlobalParam readGP = (GlobalParam) readJavaPojoFromFile(GlobalParam.class, filePath, fileName);
        Pairing pairing = PairingFactory.getPairing(readGP.getPairingParameters());
        Element ga = pairing.getG1().newElementFromBytes(readGP.getGa());
        System.out.println("new ga:= " + ga);
        System.out.println("new A:=" + readGP.getAPKS().getTMap().get("A"));
    }

}
