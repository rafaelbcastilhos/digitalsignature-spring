package com.brytecnologia.service;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class SignatureService {
    private static SignatureService INSTANCE;

    public static SignatureService getInstance() {
        if (INSTANCE == null)
            INSTANCE = new SignatureService();
        return INSTANCE;
    }

    public String signRSAwithSHA256(FileInputStream file, FileInputStream pfx, String password, String alias)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
            UnrecoverableKeyException, OperatorCreationException, CMSException {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(pfx, password.toCharArray());

        byte[] text = IOUtils.toByteArray(file);
        List<X509Certificate> certificates = new ArrayList<>();
        CMSTypedData cmsTypedData = new CMSProcessableByteArray(text);

        certificates.add((X509Certificate) keyStore.getCertificate(alias));
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

        JcaCertStore jcaCertStore = new JcaCertStore(certificates);
        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        ContentSigner signerSHA256 = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

        cmsSignedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder()
                        .setProvider("BC")
                        .build())
                .build(signerSHA256, (X509Certificate) keyStore.getCertificate(alias)));

        cmsSignedDataGenerator.addCertificates(jcaCertStore);
        CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData, false);

        return Base64
                .getEncoder()
                .encodeToString((byte[]) cmsSignedData.getSignedContent().getContent());
    }
}