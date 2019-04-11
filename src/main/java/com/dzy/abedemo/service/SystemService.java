package com.dzy.abedemo.service;

import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class SystemService {
    public static int LAMBDA = 512;
    public static String FILE_PATH = "F://edgeCPAbe";
    public static String GP_FILE_NAME = "GlobalParam.dat";
    public static int AANUMS;
    public static int ATT_NUMS;
    public static String[] AUTHORITY_NAMES;



    private GlobalParam GP;

    public GlobalParam genGlobalSystem() {
        if (GP != null)
            return GP;
        this.GP = EdgeTimeCPAbeV2.globalSetup(LAMBDA);
        String filePath = FILE_PATH + "/" + GP_FILE_NAME;
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();
        }
        EdgeTimeCPAbeV2.writeJavaPojoToFile(GP, FILE_PATH, GP_FILE_NAME);
        return GP;
    }

    public AuthorityKey[] genAuthorityKeys(int aaNums, int attNums) {
        AANUMS = aaNums;
        ATT_NUMS = attNums;
        AuthorityKey authorityKeys[] = new AuthorityKey[aaNums];
        AUTHORITY_NAMES = new String[aaNums];
        String attributes[][] = new String[aaNums][attNums];

        for (int i = 0; i < aaNums; i++) {
            AUTHORITY_NAMES[i] = "authority" + (i + 1);
            for (int j = 0; j < attNums; j++) {
                int num = i * attNums + j;
                attributes[i][j] = "" + num;
            }
            authorityKeys[i] = EdgeTimeCPAbeV2.authoritySetup(AUTHORITY_NAMES[i], GP, attributes[i]);
            String filePath = FILE_PATH + "/" + AUTHORITY_NAMES[i] + ".dat";
            File file = new File(filePath);
            if (file.exists())
                file.delete();
            EdgeTimeCPAbeV2.writeJavaPojoToFile(authorityKeys[i], FILE_PATH, AUTHORITY_NAMES[i] + ".dat");
        }
        //更新GP文件的公共参数
        File file = new File(FILE_PATH + "/" + GP_FILE_NAME);
        if (file.exists())
            file.delete();
        EdgeTimeCPAbeV2.writeJavaPojoToFile(GP, FILE_PATH, GP_FILE_NAME);
        return authorityKeys;
    }


}
