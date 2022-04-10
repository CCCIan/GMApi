package CIan.GM;

import CIan.GM.easysign.cms.gm.CMSUtil;
import CIan.GM.easysign.sign.SM2SignUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.CollectionStore;
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
import java.util.Collection;
import java.util.Iterator;

public class SM2Api {

    public String SM2EncryptHex(String publicKeyHex, String txtStr){
        final SM2 sm2 = new SM2(null, publicKeyHex);
        sm2.usePlainEncoding();
        String envStr = sm2.encryptBcd(txtStr, KeyType.PublicKey);
        return envStr;
    }

    public String SM2DecryptHex(String privateKeyHex, String txtStr){
        final SM2 sm2 = new SM2(privateKeyHex, null);
        sm2.usePlainEncoding();
        String devStr = sm2.decryptStrFromBcd(txtStr, KeyType.PrivateKey);
        return devStr;
    }

    public String SM2EncryptCert(String publicKeyCert, String txtStr) throws CertificateException, NoSuchProviderException{
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

    public String SM2DecryptPem(String privateKeyPem, String txtStr) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyFactory keyfactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec eks = new PKCS8EncodedKeySpec(Base64.decode(privateKeyPem));
        ECPrivateKey ecpPri = (ECPrivateKey) keyfactory.generatePrivate(eks);
        final SM2 sm2 = new SM2(ecpPri, null);
        sm2.usePlainEncoding();
        String devStr = sm2.decryptStrFromBcd(txtStr, KeyType.PrivateKey);
        return devStr;
    }

    public String SM2SignKeyPKCS1(String privateKeyHex, String txtStr) {
        final SM2 sm2 = new SM2(privateKeyHex, null);
        sm2.usePlainEncoding();
        byte[] sign = sm2.sign(txtStr.getBytes());
        return new String(cn.hutool.core.codec.Base64.encode(sign));
    }

    public boolean SM2VerifyKeyPKCS1(String publicKeyHex, String txtStr, String sign) {
        final SM2 sm2 = new SM2(null, publicKeyHex);
        sm2.usePlainEncoding();
        boolean verifySign = sm2.verify(txtStr.getBytes(), cn.hutool.core.codec.Base64.decode(sign.getBytes()));
        return verifySign;
    }

    public String SM2SignPemPKCS1(String privateKeyPem, String txtStr) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyFactory keyfactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec eks = new PKCS8EncodedKeySpec(cn.hutool.core.codec.Base64.decode(privateKeyPem));
        ECPrivateKey ecpPri = (ECPrivateKey) keyfactory.generatePrivate(eks);
        final SM2 sm2 = new SM2(ecpPri, null);
        sm2.usePlainEncoding();
        byte[] sign = sm2.sign(txtStr.getBytes());
        return new String(cn.hutool.core.codec.Base64.encode(sign));
    }

    public boolean SM2VerifyCertPKCS1(String publicKeyCert, String txtStr, String sign) throws CertificateException, NoSuchProviderException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        Certificate cert = factory.generateCertificate(new ByteArrayInputStream(publicKeyCert.getBytes()));
        final SM2 sm2 = new SM2(null, cert.getPublicKey());
        sm2.usePlainEncoding();
        boolean verifySign = sm2.verify(txtStr.getBytes(), cn.hutool.core.codec.Base64.decode(sign.getBytes()));
        return verifySign;
    }

    public String SM2SignPemPKCS7(String publicKeyCert, String privateKeyPem, String txtStr) throws Exception{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        InputStream inputStream = new ByteArrayInputStream(publicKeyCert.getBytes());
        X509Certificate Cert = (X509Certificate)factory.generateCertificate(inputStream);

        KeyFactory keyfactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec eks = new PKCS8EncodedKeySpec(Base64.decode(privateKeyPem));
        PrivateKey ecpPri = keyfactory.generatePrivate(eks);
        String signedValue = CMSUtil.doSM2Sign(Cert, ecpPri, txtStr.getBytes(),false);
        return signedValue;
    }

    public boolean SM2VerifyCertPKCS7(String txtStr, String sign) throws Exception{
        byte[] signdata = Base64.decode(sign);
        ByteArrayInputStream inStream = new ByteArrayInputStream((signdata));
        CMSSignedData cmsSingedData = new CMSSignedData(inStream);
//        ASN1InputStream ais = new ASN1InputStream(Base64.decode(signedData));

        //签名值
        byte[] signed = null;
        X509Certificate cert = null;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        CollectionStore x509s = (CollectionStore)cmsSingedData.getCertificates();
        X509CertificateHolder holder = (X509CertificateHolder)x509s.iterator().next();
        InputStream in = new ByteArrayInputStream(holder.getEncoded());
        cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        // 获得证书信息
        byte[] bytes = new byte[0];
        bytes = new byte[in.available()];
        in.read(bytes);
        String cer = Base64.toBase64String(bytes);
        System.out.println(cer);
        CMSTypedData cmsTypeData = cmsSingedData.getSignedContent();
        // 获得签名者信息
        Object og = cmsSingedData.getSignerInfos();
        SignerInformationStore signers = cmsSingedData.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
//            System.out.println("摘要算法 =" + signer.getDigestAlgOID());
//            System.out.println("算法 =" + signer.getEncryptionAlgOID());
            signed = signer.getSignature();
        }
//        System.out.println("签名值length=" + signed.length);
        return SM2SignUtil.verifySign(signed, txtStr.getBytes(), cert.getPublicKey());
    }
}