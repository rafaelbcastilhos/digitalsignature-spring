package com.digitalsignature.handler;

import com.digitalsignature.helper.FileHelper;
import com.digitalsignature.service.SignatureService;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class PostSignatureHandler {
    /**
     *
     * @param file é o arquivo a ser assinado
     * @param pfx é o arquivo .pfx
     * @param pfxPassword é a senha do arquivo .pfx
     * @param alias é utilizado para obter o certificado
     * @return assinatura no formato base64
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws CMSException
     */
    public String handleRequest(MultipartFile file, MultipartFile pfx, String pfxPassword, String alias)
            throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException,
            NoSuchAlgorithmException, OperatorCreationException, CMSException {

        String UPLOAD_DIRECTORY = "./resources/upload/";
        String pathFile = UPLOAD_DIRECTORY + file.getOriginalFilename();
        String pathPfx = UPLOAD_DIRECTORY + pfx.getOriginalFilename();

        FileHelper.createAndSaveOutputStream(pfx.getInputStream(), pathFile);
        FileHelper.createAndSaveOutputStream(pfx.getInputStream(), pathPfx);

        FileInputStream inputFile = new FileInputStream(pathFile);
        FileInputStream inputPfx = new FileInputStream(pathPfx);

        return SignatureService.getInstance().signRSAwithSHA256(inputFile, inputPfx, pfxPassword, alias);
    }
}
