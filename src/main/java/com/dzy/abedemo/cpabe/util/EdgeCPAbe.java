package com.dzy.abedemo.cpabe.util;


import com.dzy.abedemo.cpabe.authority.AuthSecretKey;
import com.dzy.abedemo.cpabe.authority.AuthorityKey;
import com.dzy.abedemo.cpabe.ciphertext.AccessStructure;
import com.dzy.abedemo.cpabe.ciphertext.Ciphertext;
import com.dzy.abedemo.cpabe.ciphertext.LocaleCiphertext;
import com.dzy.abedemo.cpabe.ciphertext.Message;
import com.dzy.abedemo.cpabe.globalAuthority.GlobalParam;
import com.dzy.abedemo.cpabe.timeParam.AAEncParam;
import com.dzy.abedemo.cpabe.timeParam.EncParam;
import com.dzy.abedemo.cpabe.timeParam.TimeKey;
import com.dzy.abedemo.cpabe.userKey.EdgeKeys;
import com.dzy.abedemo.cpabe.userKey.UserAuthorityKey;
import com.dzy.abedemo.cpabe.userKey.UserSplitKeys;
import com.dzy.abedemo.cpabe.userKey.Userkeys;

import java.util.Date;
import java.util.List;
import java.util.Map;

public interface EdgeCPAbe {
    abstract public GlobalParam globalSetup(int lambda);

    abstract public Userkeys userRegistry(String userID, GlobalParam GP);

    abstract public AuthorityKey authoritySetup(String authorityID, GlobalParam GP, String... attributes);

    abstract public EncParam genEncParam(GlobalParam GP, String fID, Date begin, Date end, String authority, String... attributes);

    abstract public Map<String, byte[]> extractEncParam(List<EncParam> encParam);

    abstract public void encrypt(Message message, Ciphertext ct, AccessStructure arho, GlobalParam GP, Map<String, byte[]> timeAttributes);

    abstract public UserAuthorityKey userAuthKeyGen(GlobalParam GP, String authority, AuthSecretKey sk, byte[] uUid, String... attributes);

    abstract public TimeKey timeKeysGen(String fID, byte[] uUid, AAEncParam aaEncParam, AuthSecretKey ASK, GlobalParam GP, String... attributes);

    abstract public void keysGen(List<UserAuthorityKey> userAKeys, Userkeys userkeys, String fID);

    abstract public UserSplitKeys edgeKeysGen(Userkeys userkeys, GlobalParam GP, String fID);

    abstract public Message decrypt(Ciphertext CT, Userkeys userkeys, GlobalParam GP);

    abstract public LocaleCiphertext outsourceDecrypt(Ciphertext CT, EdgeKeys edgeKeys, GlobalParam GP);

    abstract public Message localDecrypt(LocaleCiphertext LC, byte[] usk, GlobalParam GP);

}
