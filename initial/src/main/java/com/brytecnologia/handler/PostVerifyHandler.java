package com.brytecnologia.handler;

import com.brytecnologia.helper.FileHelper;
import com.brytecnologia.service.VerifyService;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.web.multipart.MultipartFile;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;

public class PostVerifyHandler {
    public String handleRequest(MultipartFile file)
            throws IOException, CertificateException, CMSException, OperatorCreationException {
        String UPLOAD_DIRECTORY = "./resources/upload/";
        String pathFile = UPLOAD_DIRECTORY + file.getOriginalFilename();

        FileHelper.createAndSaveOutputStream(file.getInputStream(), pathFile);
        FileInputStream inputSig = new FileInputStream(pathFile);

        return VerifyService.getInstance().verifySignature(inputSig);
    }
}
