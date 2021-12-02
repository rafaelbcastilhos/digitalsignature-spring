package com.brytecnologia.helper;

import java.io.*;

public class FileHelper {
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
