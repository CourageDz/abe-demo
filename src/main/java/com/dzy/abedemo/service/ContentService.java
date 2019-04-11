package com.dzy.abedemo.service;

import com.dzy.abedemo.cpabe.ciphertext.AccessStructure;
import com.dzy.abedemo.cpabe.ciphertext.Ciphertext;
import com.dzy.abedemo.cpabe.ciphertext.Message;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

@Service
public class ContentService {
    Logger log = LoggerFactory.getLogger(ContentService.class);

    @Autowired
    SystemService systemService;

    public static final String KEY_ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    public Key generateSymKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();
            log.info("origin keyBytes:=" + Arrays.toString(keyBytes));
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] symEnc(String content, Key symKey) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, symKey);
            byte[] result = cipher.doFinal(content.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public Ciphertext symKeyEnc(byte[] symKey, String policy, GlobalParam gp) {
        AccessStructure arho = AccessStructure.buildFromPolicy(policy);
//        String fID= EdgeTimeCPAbeV2.generateRandomFid();
        Message key = new Message(symKey);
        Ciphertext ciphertext = EdgeTimeCPAbeV2.normalEncrypt(key, arho, gp);
        return ciphertext;
    }
}
