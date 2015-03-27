package com.se.sample;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axiom.util.base64.Base64Utils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;

import java.security.interfaces.RSAPrivateKey;

public class AdminCallUtil {
    public static String getAuthHeader(String username) throws Exception {
        KeyStoreManager keyStoreManager;
        keyStoreManager = KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID);
        keyStoreManager.getDefaultPrimaryCertificate();
        JWSSigner signer = new RSASSASigner((RSAPrivateKey) keyStoreManager.getDefaultPrivateKey());
        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("Username", username);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS512), claimsSet);
        signedJWT.sign(signer);
        return "Bearer " + Base64Utils.encode(signedJWT.serialize().getBytes());
    }
}
