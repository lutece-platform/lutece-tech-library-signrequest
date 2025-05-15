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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class JWTRSAPlainTextAuthenticator extends AbstractJWTRSAAuthenticator
{
    String _strPlainTextPublicKey;
    String _strPlainTextPrivateKey;

    /**
     * Constructor
     * 
     * @param mapClaimsToCheck
     *            The map of claims key/values to check in the JWT
     * @param strJWTHttpHeader
     *            The name of the header which contains the JWT
     * @param lValidityPeriod
     *            The validity period
     * @param strEncryptionAlgorythmName
     *            The name of the algorithm.
     * @param strPlainTextPrivateKey
     *            The plain text private key
     * @param strPlainTextPublicKey
     *            The plain text public key
     */
    public JWTRSAPlainTextAuthenticator( Map<String, String> mapClaimsToCheck, String strJWTHttpHeader, long lValidityPeriod, String strEncryptionAlgorythmName,
            String strPlainTextPrivateKey, String strPlainTextPublicKey )
    {
        super( mapClaimsToCheck, strJWTHttpHeader, lValidityPeriod, strEncryptionAlgorythmName );
        _strPlainTextPrivateKey = strPlainTextPrivateKey;
        _strPlainTextPublicKey = strPlainTextPublicKey;

    }

    /**
     * {@inheritDoc }
     */
    @Override
    protected KeyPair getKeyPair( )
    {
        RSAPublicKey pubKey = null;
        PrivateKey privKey = null;
        try
        {
            KeyFactory kf = KeyFactory.getInstance( "RSA" );

            try
            {
                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec( Base64.getDecoder( ).decode( _strPlainTextPublicKey ) );
                pubKey = (RSAPublicKey) kf.generatePublic( keySpecX509 );
            }
            catch( InvalidKeySpecException e )
            {
                LOGGER.error( "Unable to convert given plain text key to public java.security.Key", e );
            }

            try
            {
                PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec( Base64.getDecoder( ).decode( _strPlainTextPrivateKey ) );
                privKey = kf.generatePrivate( keySpecPKCS8 );
            }
            catch( InvalidKeySpecException e )
            {
                LOGGER.error( "Unable to convert given plain text key to public java.security.Key", e );
            }
        }
        catch( NoSuchAlgorithmException e )
        {
            LOGGER.error( "Unable to obtain a KeyFactory for RSA", e );
            return null;
        }

        return new KeyPair( pubKey, privKey );
    }
}
