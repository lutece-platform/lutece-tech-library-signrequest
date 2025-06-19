/*
 * Copyright (c) 2002-2021, City of Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.util.signrequest;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import fr.paris.lutece.test.mocks.MockHttpServletRequest;
import fr.paris.lutece.util.jwt.service.JWTUtil;

/**
 * JWTSecretKeyAuthenticatorTest
 */
public class JWTRSATruststoreFileAuthenticatorTest
{
    private static final String CLAIM_KEY = "claim_key";
    private static final String CLAIM_VALUE = "claim_value";
    private static final String HTTP_HEADER_NAME = "header_name";
    private static final String ALGO = "RS256";
    private static final long VALIDITY = 60000;
    private static final String CACERT_PATH = "cacerts";
    private static final String CACERT_PASSWORD = "changeit";
    private static final String ALIAS = "wso2carbon";
    private static final String PRIV_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCsd3Tn1u9AKpWU7WXqs+p6dRboD/zbMCygGKSEYlFK/6nRa8s9vp/X9pf4i+GwgQv+dRTNeYIQgoPy7NDn9x+x30+lmzTxX9Ces1FVOUY01V69fsPzHaCBGjSjuneiKM4Ajm2oQQdMRV0ZpTfgK+qOMJzWBhxGdT+FAOAzk9FA2xqnrLLbyIXCgUPvpByZF+vVkVkAZmM6j69tWXgxa9uC5DYAdC0TrUfDxb7OiRNroDetDx11Kyvb6MOwIezWseMoSbIf1a0pWzLKzdq08UjBCmOQcqbjDFAJOKNtGdP63bcCKnCdO1jrJaCCBEi85VArIBsXUC6gBsqgka/N2I1hAgMBAAECggEAD5C/ytV8W1tci7KPV7WW4dLOgfGWHcbact/hJ+zjBF9QWXfJQeXXRvuuWelvXD7msQz/wc8Hx5YCnaVKR3KSIuYSKf1OM8Nfhes42csPrzYF/8PrSyEEkDz9Z5ItOO6bhQkAaZvmMjfdFV2deOHNy2PPdoYvqBuYji2hjoDL9SE10t6Qk5TPFHShcyZ6v8VPl2lbQ0MsB9g4ljouV4Yk+eh6lfjU6tz5o3ZT70JipmteeSb2iLHLQSRCZvPlXXobk/jW+Cu8cw6lsLPIcq45sW782FG2xGS4qSe6cLmkWihouJr9cPcXZ9Rx3P+G15Z/ibjGMbsPUSK7q8CcMYnFFwKBgQDlWuTosuGWdSS+mZ3il0NzR8oRYQI7GbdTbl5JsCjF9OGjUGEsliCQ1NJvIZj0BQGG9pAVowXCPJJ+M9NLzXpw9+C0+EdcU0ITp8flTc7I2wZgXCaBE6dnpula4HUzy/fM9nvSPK3LyohE6Nece0o+JkichXcG+tfUf90Xhg97xwKBgQDAgK3fuMmejM1hVBgbIw9afiROBee35mBDxKJNFNCZQ4hXKCk1uZA97fpiitNuZ4VPhGiNbC0iHEvAkydhjFoedWHI/kOfOFAg2IBx0NOjzOl9p5ab4/mL/dof8HtJ+7ivAKLlCuX8uUQeUJyGcClQsdnxhETHPEwEweLfLscdlwKBgF9y5lTZLPy6n6IauBQ2s0FknPmCj7UczKiSA/dSsoU/li+rIeW2TLM5fqH1L3xOIQaT0f7PK3RcVPLkioi/aLde0Us/ECOiGpundY8+RFJepFaxwuxwy3hdhDvnsZ7uwZ+w7HLgAcwP64oSBLkArjMTJ6DMAm8LMYsj81T427S9AoGBAIwsp2/jdR041kzrGWqZSxLQC8uszSDCZpKyWqTaZVNVM7CTk/6FEx2lbs/W20LnqtFOT3u7q9nM1PRzsxd7RhwryXq8e60zKlXgkRdPwuzhx5wyLp9xkEN6JB1h1cT3wXHdesBiATrYBVw1wuS6Q7t45oTRleumYoyMSpHN1DwdAoGBAISezeucX4azFaI/bQs00ibtsIYAYol4DR1gnn+QM6grnupGuDxrOTfxQEs40+tcb2efnb+Py2TJntyzh988JMRKFe73CdXufa3s7bnEHI7H5ELv7QUsH+/60JXJymilJtnfAK4fe963Vlpfw0RVByDWsynKSNZFdICGw3ZkcVAw";

    /**
     * Test of isRequestAuthenticated method, of class JWTRSATruststoreFileAuthenticatorTest.
     * 
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testSignRequestAndTestAuth( ) throws InvalidKeySpecException, NoSuchAlgorithmException, URISyntaxException
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );

        URL res = getClass( ).getClassLoader( ).getResource( CACERT_PATH );
        File file = Paths.get( res.toURI( ) ).toFile( );
        String absolutePath = file.getAbsolutePath( );

        Map<String, String> mapJWTClaims = new HashMap<>( );
        mapJWTClaims.put( CLAIM_KEY, CLAIM_VALUE );

        JWTRSATrustStoreFileAuthenticator authenticator = new JWTRSATrustStoreFileAuthenticator( mapJWTClaims, HTTP_HEADER_NAME, VALIDITY, ALGO, absolutePath,
                CACERT_PASSWORD, ALIAS );

        KeyFactory kf = KeyFactory.getInstance( "RSA" );
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec( Base64.getDecoder( ).decode( PRIV_KEY ) );
        PrivateKey privKey = kf.generatePrivate( keySpecPKCS8 );

        // Build a request with a JWT in header
        request.addHeader( HTTP_HEADER_NAME, JWTUtil.buildBase64JWT( mapJWTClaims, authenticator.getExpirationDate( ), ALGO, privKey ) );

        Assertions.assertTrue( authenticator.isRequestAuthenticated( request ) );
        Assertions.assertTrue( JWTUtil.checkPayloadValues( request, authenticator.getKeyPair( ).getPublic( ), HTTP_HEADER_NAME, mapJWTClaims ) );
    }
}
