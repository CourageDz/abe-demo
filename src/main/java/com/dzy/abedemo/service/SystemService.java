package com.dzy.abedemo.service;

import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class SystemService {
    public static int LAMBDA = 512;
    public static String FILE_PATH = "F://edgeCPAbe";

    private GlobalParam GP;

    public GlobalParam genGlobalSystem() {
        if (GP != null)
            return GP;
        this.GP = EdgeTimeCPAbeV2.globalSetup(LAMBDA);
        String fileName = "GlobalParam.dat";
        String filePath = FILE_PATH + fileName;
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();
        }
        EdgeTimeCPAbeV2.writeJavaPojoToFile(GP, FILE_PATH, fileName);
        return GP;
    }
}
