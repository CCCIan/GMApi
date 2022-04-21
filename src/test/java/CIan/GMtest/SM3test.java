package CIan.GMtest;

import CIan.GM.SM3Api;
import org.junit.Test;

public class SM3test extends SM3Api {
    @Test
    public void SM3HashTest(){
        SM3Api sm3Api = new SM3Api();
        System.out.println(sm3Api.SM3Hash("11111"));
    }


    @Test
    public void SM3HashWithSaltTest(){
        SM3Api sm3Api = new SM3Api();
        System.out.println(sm3Api.SM3HashWithSalt("11111", "1234567812345678"));
    }

}
