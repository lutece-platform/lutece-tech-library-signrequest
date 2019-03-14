/*
 * Copyright (c) 2002-2016, Mairie de Paris
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

import fr.paris.lutece.util.jwt.service.JWTUtil;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.log4j.Logger;

/**
 * AbstractAuthenticator
 */
public abstract class AbstractJWTAuthenticator implements RequestAuthenticator
{
    protected static final Logger LOGGER = Logger.getLogger( "lutece.security.signrequest" );
    protected Map<String, String> _mapClaimsToCheck;
    protected String _strJWTHttpHeader;

    /**
     * Constructor
     * 
     * @param mapClaimsToCheck
     *            The map of claims key/values to check in the JWT
     * @param strJWTHttpHeader
     *            The name of the header which contains the JWT
     */
    public AbstractJWTAuthenticator( Map<String, String> mapClaimsToCheck, String strJWTHttpHeader )
    {
        _mapClaimsToCheck = mapClaimsToCheck;
        _strJWTHttpHeader = strJWTHttpHeader;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public boolean isRequestAuthenticated( HttpServletRequest request )
    {
        // Verify if the request contains at least a JWT without checking its signature
        if ( !JWTUtil.containsUnsafeJWT( request, _strJWTHttpHeader ) )
        {
            return false;
        }

        // Verify in the JWT payload, the list of key/values to check
        if ( !JWTUtil.checkPayloadValues( request, _strJWTHttpHeader, _mapClaimsToCheck ) )
        {
            return false;
        }

        return true;
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public abstract void authenticateRequest( HttpMethodBase method, List<String> elements );

}
