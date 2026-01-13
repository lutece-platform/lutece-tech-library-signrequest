/*
 * Copyright (c) 2002-2024, City of Paris
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
package fr.paris.lutece.util.signrequest.cdi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import fr.paris.lutece.util.signrequest.HeaderHashAuthenticator;
import fr.paris.lutece.util.signrequest.IPAuthentificator;
import fr.paris.lutece.util.signrequest.JWTNoEncryptionAuthenticator;
import fr.paris.lutece.util.signrequest.JWTRSAPlainTextAuthenticator;
import fr.paris.lutece.util.signrequest.JWTRSATrustStoreFileAuthenticator;
import fr.paris.lutece.util.signrequest.JWTSecretKeyAuthenticator;
import fr.paris.lutece.util.signrequest.NoSecurityAuthenticator;
import fr.paris.lutece.util.signrequest.RequestAuthenticator;
import fr.paris.lutece.util.signrequest.RequestHashAuthenticator;
import fr.paris.lutece.util.signrequest.security.HashService;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.literal.NamedLiteral;
import jakarta.inject.Inject;

public abstract class AbstractSignRequestAuthenticatorProducer
{

    private static final String CONFIG_NAME = ".name";
    private static final String CONFIG_HASH_SERVICE = ".cfg.hashService";
    private static final String CONFIG_SIGNATURE = ".cfg.signatureElements";
    private static final String CONFIG_PRIVATE_KEY = ".cfg.privateKey";
    private static final String CONFIG_PUBLIC_KEY = ".cfg.publicKey";
    private static final String CONFIG_CLAIMS_TO_CHECK = ".cfg.claimsToCheck";
    private static final String CONFIG_TOKEN_VALIDITY_PERIOD = ".cfg.validityPeriod";
    private static final String CONFIG_TOKEN_HTTP_HEADER = ".cfg.jwtHttpHeader";
    private static final String CONFIG_ENCRYPTION_ALGORYTHM = ".cfg.encryptionAlgorythmName";
    private static final String CONFIG_SECRET_KEY = ".cfg.secretKey";
    private static final String CONFIG_CACERT_PATH = ".cfg.cacertPath";
    private static final String CONFIG_CACERT_PASSWORD = ".cfg.cacertPassword";
    private static final String CONFIG_ALIAS = ".cfg.alias";
    private static final String CONFIG_MODE = ".cfg.mode";
    private static final String CONFIG_IPS = ".cfg.ips";
    private static final String CONFIG_AUTHORIZED_PATH = ".cfg.authorizedPath";
    private static final String DEFAULT_HASH_SERVICE = "signrequest.Sha1HashService";
    
    @Inject
    private Instance<HashService> _hashServices;
    
    protected RequestAuthenticator produceRequestAuthenticator( String configPrefix )
    {
        Config _config = ConfigProvider.getConfig( );
        String strRequestAuthenticatorName = _config.getOptionalValue( configPrefix + CONFIG_NAME, String.class ).orElse( "" );
        return switch( strRequestAuthenticatorName )
        {
            case "signrequest.HeaderHashAuthenticator" ->
            {
                yield new HeaderHashAuthenticator(
                        _hashServices.select( NamedLiteral.of( _config.getOptionalValue( configPrefix + CONFIG_HASH_SERVICE, String.class ).orElse( DEFAULT_HASH_SERVICE ) ) ).get( ),
                        _config.getOptionalValues( configPrefix + CONFIG_SIGNATURE, String.class ).orElse( new ArrayList<String>( ) ),
                        _config.getOptionalValue( configPrefix + CONFIG_PRIVATE_KEY, String.class ).orElse( null ) );
            }
            case "signrequest.RequestHashAuthenticator" ->
            {
                yield new RequestHashAuthenticator(
                        _hashServices.select( NamedLiteral.of( _config.getOptionalValue( configPrefix + CONFIG_HASH_SERVICE, String.class ).orElse( DEFAULT_HASH_SERVICE ) ) ).get( ),
                        _config.getOptionalValues( configPrefix + CONFIG_SIGNATURE, String.class ).orElse( new ArrayList<String>( ) ),
                        _config.getOptionalValue( configPrefix + CONFIG_PRIVATE_KEY, String.class ).orElse( null ) );
            }
            case "signrequest.JWTNoEncryptionAuthenticator" ->
            {
                yield new JWTNoEncryptionAuthenticator(
                        _config.getOptionalValue( configPrefix + CONFIG_CLAIMS_TO_CHECK, Map.class ).orElse( new HashMap<>( 0 ) ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_HTTP_HEADER, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_VALIDITY_PERIOD, Long.class ).orElse( 60000l ) );
            }
            case "signrequest.JWTSecretKeyAuthenticator" ->
            {
                yield new JWTSecretKeyAuthenticator(
                        _config.getOptionalValue( configPrefix + CONFIG_CLAIMS_TO_CHECK, Map.class ).orElse( new HashMap<>( 0 ) ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_HTTP_HEADER, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_VALIDITY_PERIOD, Long.class ).orElse( 60000l ),
                        _config.getOptionalValue( configPrefix + CONFIG_ENCRYPTION_ALGORYTHM, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_SECRET_KEY, String.class ).orElse( null ) );
            }
            case "signrequest.JWTRSAPlainTextAuthenticator" ->
            {
                yield new JWTRSAPlainTextAuthenticator(
                        _config.getOptionalValue( configPrefix + CONFIG_CLAIMS_TO_CHECK, Map.class ).orElse( new HashMap<>( 0 ) ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_HTTP_HEADER, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_VALIDITY_PERIOD, Long.class ).orElse( 60000l ),
                        _config.getOptionalValue( configPrefix + CONFIG_ENCRYPTION_ALGORYTHM, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_PRIVATE_KEY, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_PUBLIC_KEY, String.class ).orElse( null ) );
            }
            case "signrequest.JWTRSATrustStoreFileAuthenticator" ->
            {
                yield new JWTRSATrustStoreFileAuthenticator(
                        _config.getOptionalValue( configPrefix + CONFIG_CLAIMS_TO_CHECK, Map.class ).orElse( new HashMap<>( 0 ) ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_HTTP_HEADER, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_TOKEN_VALIDITY_PERIOD, Long.class ).orElse( 60000l ),
                        _config.getOptionalValue( configPrefix + CONFIG_ENCRYPTION_ALGORYTHM, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_CACERT_PATH, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_CACERT_PASSWORD, String.class ).orElse( null ),
                        _config.getOptionalValue( configPrefix + CONFIG_ALIAS, String.class ).orElse( null ) );
            }
            case "signrequest.IPAuthenticator" ->
            {
                yield new IPAuthentificator( 
                        _config.getOptionalValue( configPrefix + CONFIG_MODE, String.class ).orElse( null ),
                        _config.getOptionalValues( configPrefix + CONFIG_IPS, String.class ).orElse( new ArrayList<String>( ) ),
                        _config.getOptionalValues( configPrefix + CONFIG_AUTHORIZED_PATH, String.class ).orElse( new ArrayList<String>( ) ));
            }
            default -> new NoSecurityAuthenticator( );
        };
    }

}
