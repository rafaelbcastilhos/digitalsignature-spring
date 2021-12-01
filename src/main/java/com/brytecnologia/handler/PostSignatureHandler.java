package com.brytecnologia.handler;

import com.brytecnologia.service.SignatureService;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class PostSignatureHandler {
    private static String UPLOAD_DIR = "/home/rafaelbcastilhos/Downloads/DesafioAPIv3/resources/upload/";

    public String handleRequest(MultipartFile file, MultipartFile pfx, String pfxPassword, String alias)
            throws IOException, UnrecoverableKeyException, CertificateException,
            KeyStoreException, NoSuchAlgorithmException, OperatorCreationException,
            CMSException {

        String nomePfx = pfx.getOriginalFilename();
        String nomeArquivo = file.getOriginalFilename();
        String path = UPLOAD_DIR + File.separator;
        System.out.println(nomePfx);
        saveFile(pfx.getInputStream(), path + nomePfx);
        saveFile(pfx.getInputStream(), path + nomeArquivo);

        FileInputStream inputPfx = new FileInputStream(path+nomePfx);
        FileInputStream inputArq = new FileInputStream(path+nomeArquivo);

        return SignatureService.getInstance().signRSAwithSHA256(inputArq, inputPfx, pfxPassword, alias);
    }

    private void saveFile(InputStream inputStream, String path) {
        try {
            OutputStream outputStream = new FileOutputStream(new File(path));
            int read = 0;
            byte[] bytes = new byte[1024];
            while ((read = inputStream.read(bytes)) != -1) {
                outputStream.write(bytes, 0, read);
            }
            outputStream.flush();
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
