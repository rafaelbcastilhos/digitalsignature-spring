package com.brytecnologia.service;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

public class VerifyService {
    private static VerifyService INSTANCE;

    public static VerifyService getInstance() {
        if(INSTANCE == null)
            INSTANCE = new VerifyService();
        return INSTANCE;
    }

    /**
     * Verifica assinatura gerada
     */
    public static String verifySignature(FileInputStream file)
            throws IOException, CMSException, CertificateException, OperatorCreationException {
        boolean valid = false;

        FileInputStream signatureFileStream = null;
        signatureFileStream = new FileInputStream("./resources/arquivos/signature.p7s");

        byte[] signatureBytes = IOUtils.toByteArray(signatureFileStream);
        byte[] cmsBytes = null;
        cmsBytes = IOUtils.toByteArray(file);

        Security.addProvider(new BouncyCastleProvider());
        CMSSignedData signedData = null;
        CMSProcessableByteArray processableByteArray = new CMSProcessableByteArray(cmsBytes);
        signedData = new CMSSignedData(processableByteArray, signatureBytes);

        Store<X509CertificateHolder> store = signedData.getCertificates();
        SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        Collection<SignerInformation> signerInformationCollection = signerInformationStore.getSigners();

        for (SignerInformation signerInformation : signerInformationCollection) {
            Collection collection = ((CollectionStore) store).getMatches(signerInformation.getSID());
            Iterator iterator = collection.iterator();
            X509CertificateHolder certificateHolder = (X509CertificateHolder) iterator.next();
            X509Certificate certificate = null;

            certificate = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(certificateHolder);

            if (signerInformation.verify(
                    new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate)))
                valid = true;
        }
        return valid ? "VÁLIDO" : "INVÁLIDO";
    }
}
