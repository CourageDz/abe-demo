package com.dzy.abedemo.cpabe.ciphertext;


import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;

import java.io.*;
import java.util.*;

public class Ciphertext implements Serializable {
    private static final long serialVersionUID = 1L;
    private String fID;
    private byte[] c0;
    private byte[] c1;
    private List<byte[]> c2;
    private List<byte[]> c3;
    private List<byte[]> c4;
    private Set<String> authorities;
    private AccessStructure accessStructure;

    public Ciphertext() {
        authorities = new HashSet<>();
        c2 = new ArrayList<>();
        c3 = new ArrayList<byte[]>();
        c4 = new ArrayList<byte[]>();
    }

    public Ciphertext(int n) {
        authorities = new HashSet<>();
        c2 = new ArrayList<>(n);
        c3 = new ArrayList<byte[]>(n);
        c4 = new ArrayList<byte[]>(n);
    }

    public void setfID(String fID) {
        this.fID = fID;
    }

    public String getfID() {
        return fID;
    }


    public byte[] getC0() {
        return c0;
    }

    public void setC0(byte[] c0) {
        this.c0 = c0;
    }

    public byte[] getC1() {
        return c1;
    }

    public void setC1(byte[] c1x) {
        this.c1 = c1x;
    }


    public byte[] getC2(int x) {
        return this.c2.get(x);
    }

    public void setC2(byte[] c2x) {
        this.c2.add(c2x);
    }

    public void setC2(byte[] c2x, int index) {
        this.c2.add(index, c2x);
    }

    public List<byte[]> getC2() {
        return c2;
    }

    public byte[] getC3(int x) {
        return c3.get(x);
    }

    public void setC3(byte[] c3x) {
        this.c3.add(c3x);
    }

    public void setC3(byte[] c3x, int index) {
        this.c3.add(index, c3x);
    }

    public byte[] getC4(int x) {
        return c4.get(x);
    }

    public void setC4(byte[] c4x) {
        this.c4.add(c4x);
    }

    public void setC4(byte[] c4x, int index) {
        this.c4.add(index, c4x);
    }

    public AccessStructure getAccessStructure() {
        return accessStructure;
    }

    public void setAccessStructure(AccessStructure accessStructure) {
        this.accessStructure = accessStructure;
    }

    public Set<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Set<String> authorities) {
        this.authorities = authorities;
    }

    public static void main(String[] args) {
        GlobalParam GP = EdgeTimeCPAbeV2.globalSetup(512);

        Message m = EdgeTimeCPAbeV2.generateRandomMessage(GP);
        String policy = "and and a b  or c and d e";
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);

        Ciphertext ct = EdgeTimeCPAbeV2.normalEncrypt(m, arho, GP);
        System.out.println("C0=" + Arrays.toString(ct.getC0()));
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("F://edgeCPAbe/ciphertext.dat"));
            out.writeObject(ct);
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Ciphertext readct = new Ciphertext();
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream("F://edgeCPAbe/ciphertext.dat"));
            readct = (Ciphertext) in.readObject();
            in.close();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("CT.co=" + Arrays.toString(readct.getC0()));
    }
}
