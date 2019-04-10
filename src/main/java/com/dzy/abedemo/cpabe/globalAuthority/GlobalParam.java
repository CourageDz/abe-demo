package com.dzy.abedemo.cpabe.globalAuthority;

import com.dzy.abedemo.cpabe.authority.AuthorityPublicKeys;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;

public class GlobalParam implements Serializable {
    private long id;
    private static final long serialVersionUID = 1L;
    private PairingParameters pairingParameters;
    private AuthorityPublicKeys APKS;
    private byte[] g;
    private byte[] ga;

    public GlobalParam() {
        this.APKS = new AuthorityPublicKeys();
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public void setPairingParameters(PairingParameters pairingParameters) {
        this.pairingParameters = pairingParameters;
    }

    public byte[] getG() {
        return g;
    }

    public void setG(byte[] g) {
        this.g = g;
    }

    public byte[] getGa() {
        return ga;
    }

    public void setGa(byte[] ga) {
        this.ga = ga;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public AuthorityPublicKeys getAPKS() {
        return APKS;
    }

    public static void main(String[] args) {
        GlobalParam gp = EdgeTimeCPAbeV2.globalSetup(512);
        Pairing oldPairing = PairingFactory.getPairing(gp.pairingParameters);
        Element oldGa = oldPairing.getG1().newElementFromBytes(gp.getGa());
        gp.getAPKS().getTMap().put("A", "1");
        System.out.println("origanal ga:=" + oldGa);
        System.out.println("orginal A:=" + gp.getAPKS().getTMap().get("A"));
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/GlobalParam.dat"));
            out.writeObject(gp);
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        GlobalParam readGP = new GlobalParam();
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/GlobalParam.dat"));
            readGP = (GlobalParam) in.readObject();
            in.close();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Pairing pairing = PairingFactory.getPairing(readGP.getPairingParameters());
        Element ga = pairing.getG1().newElementFromBytes(readGP.ga);
        System.out.println("new ga:= " + ga);
        System.out.println("new A:=" + readGP.getAPKS().getTMap().get("A"));
    }
}
