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

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import fr.paris.lutece.test.mocks.MockHttpServletRequest;
import fr.paris.lutece.util.jwt.service.JWTUtil;

/**
 * JWTNoEncryptionAuthenticatorTest
 */
public class JWTNoEncryptionAuthenticatorTest
{
    private static final String CLAIM_KEY = "claim_key";
    private static final String CLAIM_VALUE = "claim_value";
    private static final String HTTP_HEADER_NAME = "header_name";
    private static final long VALIDITY = 60000;

    /**
     * Test of isRequestAuthenticated method, of class JWTNoEncryptionAuthenticator.
     */
    @Test
    public void testSignRequestAndTestAuth( )
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );

        Map<String, String> mapJWTClaims = new HashMap<>( );
        mapJWTClaims.put( CLAIM_KEY, CLAIM_VALUE );

        // Build a request with a JWT in header
        JWTNoEncryptionAuthenticator authenticator = new JWTNoEncryptionAuthenticator( mapJWTClaims, HTTP_HEADER_NAME, VALIDITY );
        request.addHeader( HTTP_HEADER_NAME, JWTUtil.buildBase64JWT( mapJWTClaims, authenticator.getExpirationDate( ), null, null ) );

        Assertions.assertTrue( authenticator.isRequestAuthenticated( request ) );
        Assertions.assertTrue( JWTUtil.checkPayloadValues( request, HTTP_HEADER_NAME, mapJWTClaims ) );
    }
}
