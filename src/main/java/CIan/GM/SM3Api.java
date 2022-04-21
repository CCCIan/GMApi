package CIan.GM;

import cn.hutool.crypto.digest.SM3;

public class SM3Api {
    public String SM3Hash(String txtStr){
        final SM3 sm3 = new SM3();
        return sm3.digestHex(txtStr);
    }

    public String SM3HashWithSalt(String txtStr, String salt){
        final SM3 sm3 = (SM3) new SM3().setSalt(salt.getBytes());
        return sm3.digestHex(txtStr);
    }
}
