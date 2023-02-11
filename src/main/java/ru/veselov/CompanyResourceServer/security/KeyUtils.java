package ru.veselov.CompanyResourceServer.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

@Component
@Slf4j
public class KeyUtils {

    @Autowired
    Environment environment;
    @Value("${access-token.private}")
    private String accessTokenPrivateKeyPath;

    @Value("${access-token.public}")
    private String accessTokenPublicKeyPath;

    @Value("${refresh-token.private}")
    private String refreshTokenPrivateKeyPath;

    @Value("${refresh-token.public}")
    private String refreshTokenPublicKeyPath;


    private KeyPair accessTokenKeyPair;
    private KeyPair refreshTokenKeyPair;

    public RSAPublicKey getAccessTokenPublicKey(){
        return (RSAPublicKey) getAccessTokenKeyPair().getPublic();
    }

    public RSAPrivateKey getAccessTokenPrivateKey(){
        return (RSAPrivateKey) getAccessTokenKeyPair().getPrivate();
    }
    public RSAPublicKey getRefreshTokenPublicKey(){
        return (RSAPublicKey) getRefreshTokenKeyPair().getPublic();
    }

    public RSAPrivateKey getRefreshTokenPrivateKey(){
        return (RSAPrivateKey) getRefreshTokenKeyPair().getPrivate();
    }

    private KeyPair getAccessTokenKeyPair(){
        if(Objects.isNull(accessTokenKeyPair)){
            accessTokenKeyPair=getKeyPair(accessTokenPublicKeyPath,accessTokenPrivateKeyPath);
        }
        return accessTokenKeyPair;
    }

    private KeyPair getRefreshTokenKeyPair() {
        if(Objects.isNull(refreshTokenKeyPair)){
            refreshTokenKeyPair=getKeyPair(refreshTokenPublicKeyPath,refreshTokenPrivateKeyPath);
        }
        return refreshTokenKeyPair;
    }



    private KeyPair getKeyPair(String publicKeyPath, String privateKeyPath){
        /*creating files with keys, in dev profile keys will be generated and saved into files,
        * in prod profile - if key files don't exist exception will be thrown,
        * so need to check if key files already here*/
        KeyPair keyPair;
        File publicKeyFile = new File(publicKeyPath);
        File privateKeyFile = new File(privateKeyPath);

        if(publicKeyFile.exists() && privateKeyFile.exists()){
            log.info("Loading files {} , {}",publicKeyPath, privateKeyPath);
            try{
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
                EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                keyPair = new KeyPair(publicKey,privateKey);
                return keyPair;
            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
        else {
            if(Arrays.asList(environment.getActiveProfiles()).contains("prod")){
                throw new RuntimeException("private and public keys doesn't exists");
            }
        }
        File directory = new File("token-keys");
        if(!directory.exists()){
            directory.mkdirs();
        }
        //creating rsa key generator for writing keys to files
        try{
            log.info("Generating new public and private keys {}, {}", publicKeyPath, privateKeyPath);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair=keyPairGenerator.generateKeyPair();
            try(FileOutputStream fos = new FileOutputStream(publicKeyPath)){
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
                fos.write(keySpec.getEncoded());
            }
            try(FileOutputStream fos = new FileOutputStream(privateKeyPath)){
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
                fos.write(keySpec.getEncoded());
            }             }
        catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
        return keyPair;
    }

}
