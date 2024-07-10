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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

public class JWTRSAKeyStoreFileAuthenticator extends AbstractJWTRSAAuthenticator
{
    private final String _strKeystorePath;
    private final String _strKeystorePassword;
    private final String _strCertificatePassword;
    private final String _strAlias;

    /**
     * {@inheritDoc }
     */
    @Override
    public boolean isRequestAuthenticated( HttpServletRequest request )
    {
        // WARNING
        // Be careful when your using the KeyStoreFileAuthenticator to sign request.
        // This implementation can be used from request inside the same server; because
        // its requires the keystore which contains both private and public keys. Do
        // not use it if your are client/server request mode, as API calls. See doc
        // for more informations.
        return super.isRequestAuthenticated( request );
    }

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
     * @param strKeystorePath
     *            The path of the keystore
     * @param strKeystorePassword
     *            The password of the keystore
     * @param strCertificatePassword
     *            The pass of the certificate
     * @param strAlias
     *            The alias of the certificate in the keystore
     */
    public JWTRSAKeyStoreFileAuthenticator( Map<String, String> mapClaimsToCheck, String strJWTHttpHeader, long lValidityPeriod,
            String strEncryptionAlgorythmName, String strKeystorePath, String strKeystorePassword, String strCertificatePassword, String strAlias )
    {
        super( mapClaimsToCheck, strJWTHttpHeader, lValidityPeriod, strEncryptionAlgorythmName );
        _strKeystorePath = strKeystorePath;
        _strKeystorePassword = strKeystorePassword;
        _strCertificatePassword = strCertificatePassword;
        _strAlias = strAlias;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    protected KeyPair getKeyPair( )
    {
        try
        {
            FileInputStream is = new FileInputStream( _strKeystorePath );
            KeyStore keystore = KeyStore.getInstance( KeyStore.getDefaultType( ) );
            keystore.load( is, _strKeystorePassword.toCharArray( ) );

            Key key = (PrivateKey) keystore.getKey( _strAlias, _strCertificatePassword.toCharArray( ) );
            Certificate cert = keystore.getCertificate( _strAlias );
            PublicKey publicKey = cert.getPublicKey( );

            return new KeyPair( publicKey, (PrivateKey) key );
        }

        catch( CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e )
        {
            LOGGER.error( "Unable to get key pair from certificate", e );
        }

        return null;
    }
}
