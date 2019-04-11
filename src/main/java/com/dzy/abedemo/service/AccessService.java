package com.dzy.abedemo.service;

import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.userKey.CertUid;
import com.dzy.abedemo.cpabe.userKey.UserAuthorityKey;
import com.dzy.abedemo.cpabe.util.EdgeTimeCPAbeV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
public class AccessService {
    Logger log = LoggerFactory.getLogger(AccessService.class);


    public GlobalParam getGlobalParam() {
        GlobalParam GP;
        try {
            GP = (GlobalParam) EdgeTimeCPAbeV2.readJavaPojoFromFile(GlobalParam.class, SystemService.FILE_PATH, SystemService.GP_FILE_NAME);
            return GP;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public CertUid registerUser(GlobalParam gp, long userId) {
        return EdgeTimeCPAbeV2.userRegistry(gp, "" + userId);
    }

    public UserAuthorityKey[] getUserAAKeys(GlobalParam gp, String duAttributes) {

        if (SystemService.AANUMS <= 0) {
            log.info("system hasn't inited!");
            return null;
        }
        UserAuthorityKey[] uaks = new UserAuthorityKey[SystemService.AANUMS];
        Map<String, String> authorityMap = gp.getAPKS().getTMap();
        Map<String, Set<String>> attributesMap = sortDuAttributes(duAttributes, authorityMap);
        for (int i = 0; i < SystemService.AANUMS; i++) {
            String[] authoritys = SystemService.AUTHORITY_NAMES;
//            uaks[i]=EdgeTimeCPAbeV2.userAuthKeyGen(gp,authoritys[i],authorityKeys[i].getSecretKey(),certUid,attributes[i]);
        }
        return null;
    }

    public Map<String, Set<String>> sortDuAttributes(String duAttributes, Map<String, String> aaMap) {
        String[] attributes = duAttributes.split(" ");
        Map<String, Set<String>> attributesMap = new HashMap<>();
        for (String attribute : attributes) {
            String authority = aaMap.get(attribute);
            attributesMap.computeIfAbsent(authority, k -> new HashSet<String>()).add(attribute);
        }
        return attributesMap;
    }
}
