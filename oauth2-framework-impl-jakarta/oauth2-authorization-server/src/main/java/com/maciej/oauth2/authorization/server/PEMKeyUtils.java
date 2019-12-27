package com.maciej.oauth2.authorization.server;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static java.lang.Thread.currentThread;

public class PEMKeyUtils {

    public static String readKeyAsString(String verificationKey) throws IOException, URISyntaxException {
        URI uri = currentThread().getContextClassLoader().getResource(verificationKey).toURI();
        byte[] byteArray = Files.readAllBytes(Paths.get(uri));
        return new String(byteArray);
    }
}
