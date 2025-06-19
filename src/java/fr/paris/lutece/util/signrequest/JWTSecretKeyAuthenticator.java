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

import java.security.Key;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import fr.paris.lutece.util.jwt.service.JWTUtil;

public class JWTSecretKeyAuthenticator extends AbstractJWTAuthenticator
{
    private String _strSecretKey;
    private String _strEncryptionAlgorythmName;
    private final String DEFAULT_ENC_ALGO_NAME = "HS256";

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
     *            The name of the algorithm. Values are HS256, HS384, HS512
     * @param strSecretKey
     *            The secret key
     */
    public JWTSecretKeyAuthenticator( Map<String, String> mapClaimsToCheck, String strJWTHttpHeader, long lValidityPeriod, String strEncryptionAlgorythmName,
            String strSecretKey )
    {
        super( mapClaimsToCheck, strJWTHttpHeader, lValidityPeriod );
        _strSecretKey = strSecretKey;
        _strEncryptionAlgorythmName = strEncryptionAlgorythmName;

        if ( _strEncryptionAlgorythmName == null )
        {
            _strEncryptionAlgorythmName = DEFAULT_ENC_ALGO_NAME;
        }
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public boolean isRequestAuthenticated( HttpServletRequest request )
    {
        Key key = JWTUtil.getKey( _strSecretKey, _strEncryptionAlgorythmName );
        boolean validSignature = JWTUtil.checkSignature( request, _strJWTHttpHeader, key );

        if ( validSignature )
        {
            return super.isRequestAuthenticated( request, key );
        }
        return false;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public AuthenticateRequestInformations  getSecurityInformations( List<String> elements )
    {
        Key key = JWTUtil.getKey( _strSecretKey, _strEncryptionAlgorythmName );
        
        return new AuthenticateRequestInformations().addSecurityHeader( _strJWTHttpHeader, JWTUtil.buildBase64JWT( _mapClaimsToCheck, getExpirationDate( ), _strEncryptionAlgorythmName, key ) );
    
    }
}
