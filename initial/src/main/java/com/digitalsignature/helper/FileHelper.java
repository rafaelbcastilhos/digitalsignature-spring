package com.digitalsignature.helper;

import java.io.*;

public class FileHelper {

    /**
     * Dada a entrada em InputStream, cria um arquivo no caminho indicado e determinada a saída
     */
    public static void createAndSaveOutputStream(InputStream inputStream, String path) throws IOException {
        OutputStream outputStream = new FileOutputStream(path);
        int read = 0;
        byte[] bytes = new byte[1024];
        while ((read = inputStream.read(bytes)) != -1)
            outputStream.write(bytes, 0, read);

        outputStream.flush();
        outputStream.close();
    }
}
