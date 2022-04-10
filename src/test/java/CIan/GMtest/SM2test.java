package CIan.GMtest;

import CIan.GM.SM2Api;
import org.junit.Test;

public class SM2test extends SM2Api {
    @Test
    public void SM2EnDeHexTest() throws Exception{
        String str = "everything";
        String publicKeyHex = "04538F505772EE2FAC65AD8BAB8627A2ED1DC17157A8064FD8A4F187A97EDF90ABD0967BA251918A6B11F76F2A3D3A7AE7251C79419CAAB8C2B109FD217AE462ED";
        SM2Api sm2Api = new SM2Api();
        String enStr = sm2Api.SM2EncryptHex(publicKeyHex, str);
        System.out.println("十六进制公钥串加密密文:" + enStr);
        String privateKeyHex = "586EE18A94B0D2CE3253F5A385F57CBCBB5A7E98B6E0CDE32777EF89B77A6D01";
        String deStr = sm2Api.SM2DecryptHex(privateKeyHex, enStr);
        System.out.println("十六进制私钥串解密明文:" + deStr);
    }

    @Test
    public void SM2EnDePemCertTest() throws Exception{
        String str = "everything";
        String certInfo = "-----BEGIN CERTIFICATE-----\r\n"
                + "MIIBrTCCAVICCQCxYpYSzXCIRzAKBggqgRzPVQGDdTBeMQswCQYDVQQGEwJDTjEL\r\n"
                + "MAkGA1UECAwCSEYxCzAJBgNVBAcMAkhGMQ8wDQYDVQQKDAZIU0JBTksxDTALBgNV\r\n"
                + "BAsMBFRFU1QxFTATBgNVBAMMDFRFU1QgTUVSQ0hOVDAeFw0yMTExMDgwNjU4Mzla\r\n"
                + "Fw0zMTExMDYwNjU4MzlaMF4xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJIRjELMAkG\r\n"
                + "A1UEBwwCSEYxDzANBgNVBAoMBkhTQkFOSzENMAsGA1UECwwEVEVTVDEVMBMGA1UE\r\n"
                + "AwwMVEVTVCBNRVJDSE5UMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEK5LRFTv\r\n"
                + "uODEaW1GWPLsT1PwyOs4KyKUA5OT92BD5mmqCNejc+x4WYaT2sTArkiH4At8C4xl\r\n"
                + "Eq15hSuxBt95hDAKBggqgRzPVQGDdQNJADBGAiEA2tMG8OCrzQ7485duxy+ZtOBK\r\n"
                + "qoBoIGNNUOT4DFo236YCIQDOkzg47NsjiLzXVpzfF4hS41QPFgY5yWD+OM2KNy+U\r\n" + "jw==\r\n"
                + "-----END CERTIFICATE-----";
        SM2Api sm2Api = new SM2Api();
        String enStr = sm2Api.SM2EncryptCert(certInfo, str);
        System.out.println("Cert证书加密密文:" + enStr);
        String privatePem = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg1eGvibIkTl8gsrE76MhYb7rn6wv34uul59OSKh8Q1i2hRANCAAQQrktEVO+44MRpbUZY8uxPU/DI6zgrIpQDk5P3YEPmaaoI16Nz7HhZhpPaxMCuSIfgC3wLjGUSrXmFK7EG33mE";
        String deStr = sm2Api.SM2DecryptPem(privatePem, enStr);
        System.out.println("Pem私钥解密明文:" + deStr);
    }

    @Test
    public void SM2PKCS1SignHexTest() throws Exception{
        String str = "everything";
        String privateKeyHex = "586EE18A94B0D2CE3253F5A385F57CBCBB5A7E98B6E0CDE32777EF89B77A6D01";
        SM2Api sm2Api = new SM2Api();
        String sign = sm2Api.SM2SignKeyPKCS1(privateKeyHex, str);
        System.out.println("十六进制PKCS1签名：" + sign);
        String publicKeyHex = "04538F505772EE2FAC65AD8BAB8627A2ED1DC17157A8064FD8A4F187A97EDF90ABD0967BA251918A6B11F76F2A3D3A7AE7251C79419CAAB8C2B109FD217AE462ED";
        boolean verify = sm2Api.SM2VerifyKeyPKCS1(publicKeyHex, str, sign);
        System.out.println("十六进制PKCS1验签：" + verify);
    }

    @Test
    public void SM2PKCS1SignCertPemTest() throws Exception{
        String str = "everything";
        String privatePem = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg1eGvibIkTl8gsrE76MhYb7rn6wv34uul59OSKh8Q1i2hRANCAAQQrktEVO+44MRpbUZY8uxPU/DI6zgrIpQDk5P3YEPmaaoI16Nz7HhZhpPaxMCuSIfgC3wLjGUSrXmFK7EG33mE";
        SM2Api sm2Api = new SM2Api();
        String sign = sm2Api.SM2SignPemPKCS1(privatePem, str);
        System.out.println("PemPKCS1签名：" + sign);
        String certInfo = "-----BEGIN CERTIFICATE-----\r\n"
                + "MIIBrTCCAVICCQCxYpYSzXCIRzAKBggqgRzPVQGDdTBeMQswCQYDVQQGEwJDTjEL\r\n"
                + "MAkGA1UECAwCSEYxCzAJBgNVBAcMAkhGMQ8wDQYDVQQKDAZIU0JBTksxDTALBgNV\r\n"
                + "BAsMBFRFU1QxFTATBgNVBAMMDFRFU1QgTUVSQ0hOVDAeFw0yMTExMDgwNjU4Mzla\r\n"
                + "Fw0zMTExMDYwNjU4MzlaMF4xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJIRjELMAkG\r\n"
                + "A1UEBwwCSEYxDzANBgNVBAoMBkhTQkFOSzENMAsGA1UECwwEVEVTVDEVMBMGA1UE\r\n"
                + "AwwMVEVTVCBNRVJDSE5UMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEK5LRFTv\r\n"
                + "uODEaW1GWPLsT1PwyOs4KyKUA5OT92BD5mmqCNejc+x4WYaT2sTArkiH4At8C4xl\r\n"
                + "Eq15hSuxBt95hDAKBggqgRzPVQGDdQNJADBGAiEA2tMG8OCrzQ7485duxy+ZtOBK\r\n"
                + "qoBoIGNNUOT4DFo236YCIQDOkzg47NsjiLzXVpzfF4hS41QPFgY5yWD+OM2KNy+U\r\n" + "jw==\r\n"
                + "-----END CERTIFICATE-----";
        boolean verify = sm2Api.SM2VerifyCertPKCS1(certInfo, str, sign);
        System.out.println("CertPKCS1验签：" + verify);
    }

    @Test
    public void SM2PKCS7SignCertPemTest() throws Exception{
        String str = "everything";
        String privatePem = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg1eGvibIkTl8gsrE76MhYb7rn6wv34uul59OSKh8Q1i2hRANCAAQQrktEVO+44MRpbUZY8uxPU/DI6zgrIpQDk5P3YEPmaaoI16Nz7HhZhpPaxMCuSIfgC3wLjGUSrXmFK7EG33mE";
        SM2Api sm2Api = new SM2Api();
        String certInfo = "-----BEGIN CERTIFICATE-----\r\n"
                + "MIIBrTCCAVICCQCxYpYSzXCIRzAKBggqgRzPVQGDdTBeMQswCQYDVQQGEwJDTjEL\r\n"
                + "MAkGA1UECAwCSEYxCzAJBgNVBAcMAkhGMQ8wDQYDVQQKDAZIU0JBTksxDTALBgNV\r\n"
                + "BAsMBFRFU1QxFTATBgNVBAMMDFRFU1QgTUVSQ0hOVDAeFw0yMTExMDgwNjU4Mzla\r\n"
                + "Fw0zMTExMDYwNjU4MzlaMF4xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJIRjELMAkG\r\n"
                + "A1UEBwwCSEYxDzANBgNVBAoMBkhTQkFOSzENMAsGA1UECwwEVEVTVDEVMBMGA1UE\r\n"
                + "AwwMVEVTVCBNRVJDSE5UMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEK5LRFTv\r\n"
                + "uODEaW1GWPLsT1PwyOs4KyKUA5OT92BD5mmqCNejc+x4WYaT2sTArkiH4At8C4xl\r\n"
                + "Eq15hSuxBt95hDAKBggqgRzPVQGDdQNJADBGAiEA2tMG8OCrzQ7485duxy+ZtOBK\r\n"
                + "qoBoIGNNUOT4DFo236YCIQDOkzg47NsjiLzXVpzfF4hS41QPFgY5yWD+OM2KNy+U\r\n" + "jw==\r\n"
                + "-----END CERTIFICATE-----";
        String sign = sm2Api.SM2SignPemPKCS7(certInfo, privatePem, str);
        System.out.println("PemPKCS7签名：" + sign);
        boolean verify = sm2Api.SM2VerifyCertPKCS7(str, sign);
        System.out.println("CertPKCS7验签：" + verify);
    }
}

