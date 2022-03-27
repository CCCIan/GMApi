package CIan.GM;

import CIan.GM.easysign.cms.gm.CMSUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class SM2Api {

    public String SM2DecryptHex(String privateKeyHex, String txtStr){
        final SM2 sm2 = new SM2(privateKeyHex, null);
        sm2.usePlainEncoding();
        String devStr = sm2.decryptStrFromBcd(txtStr, KeyType.PrivateKey);
        return devStr;
    }

    public String SM2DecryptPem(String privateKeyPem, String txtStr) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
        KeyFactory keyfactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec eks = new PKCS8EncodedKeySpec(Base64.decode(privateKeyPem));
        ECPrivateKey ecpPri = (ECPrivateKey) keyfactory.generatePrivate(eks);
        final SM2 sm2 = new SM2(ecpPri, null);
        sm2.usePlainEncoding();
        String devStr = sm2.decryptStrFromBcd(txtStr, KeyType.PrivateKey);
        return devStr;
    }

    public String SM2EncryptHex(String publicKeyHex, String txtStr){
        final SM2 sm2 = new SM2(null, publicKeyHex);
        sm2.usePlainEncoding();
        String envStr = sm2.encryptBcd(txtStr, KeyType.PublicKey);
        return envStr;
    }

    public String SM2EncryptPem(String publicKeyCert, String txtStr) throws CertificateException, NoSuchProviderException{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        Certificate cert = factory.generateCertificate(new ByteArrayInputStream(publicKeyCert.getBytes()));
        final SM2 sm2 = new SM2(null, cert.getPublicKey());
        sm2.usePlainEncoding();
        String envStr = sm2.encryptBcd(txtStr, KeyType.PublicKey);
        return envStr;
    }

    public static String SM2SignPemPKCS7(String publicKeyCert, String privateKeyPem, String txtStr) throws Exception{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        InputStream inputStream   =   new   ByteArrayInputStream(publicKeyCert.getBytes());
        X509Certificate Cert = (X509Certificate)factory.generateCertificate(inputStream);

        KeyFactory keyfactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec eks = new PKCS8EncodedKeySpec(Base64.decode(privateKeyPem));
        PrivateKey ecpPri = keyfactory.generatePrivate(eks);
        String signedValue = CMSUtil.doSM2Sign(Cert, ecpPri, txtStr.getBytes(),false);
        return signedValue;
    }

    public static void main(String[] args) throws Exception{
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
        String privatePem = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg1eGvibIkTl8gsrE76MhYb7rn6wv34uul59OSKh8Q1i2hRANCAAQQrktEVO+44MRpbUZY8uxPU/DI6zgrIpQDk5P3YEPmaaoI16Nz7HhZhpPaxMCuSIfgC3wLjGUSrXmFK7EG33mE";
        System.out.println(SM2SignPemPKCS7(certInfo, privatePem, str));
    }
}
