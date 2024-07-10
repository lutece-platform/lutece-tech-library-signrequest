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
package fr.paris.lutece.util.signrequest.servlet;

import fr.paris.lutece.util.signrequest.AbstractAuthenticator;
import fr.paris.lutece.util.signrequest.AbstractPrivateKeyAuthenticator;
import fr.paris.lutece.util.signrequest.security.Sha1HashService;

import java.io.IOException;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * SimpleHash Sign Request Filter
 */
public abstract class AbstractRequestFilter implements Filter
{
    private static final String PARAMETER_PRIVATE_KEY = "privateKey";
    private static final String PARAMETER_ELEMENTS_SIGNATURE = "elementsSignature";
    private static final String PARAMETER_VALIDITY_PERIOD = "validityTimePeriod";
    private AbstractAuthenticator _authenticator;

    /**
     * The implementation should provide the authenticator to use
     * 
     * @return The authenticator to be used by the filter
     */
    protected abstract AbstractAuthenticator getAuthenticator( );

    /**
     * {@inheritDoc }
     */
    @Override
    public void init( FilterConfig filterConfig ) throws ServletException
    {
        _authenticator = getAuthenticator( );

        // Set the Hashing service
        _authenticator.setHashService( new Sha1HashService( ) );

        if ( _authenticator instanceof AbstractPrivateKeyAuthenticator )
        {
            // Set the shared secret between client and server
            String strPrivateKey = filterConfig.getInitParameter( PARAMETER_PRIVATE_KEY );
            ( (AbstractPrivateKeyAuthenticator) _authenticator ).setPrivateKey( strPrivateKey );
        }

        // Set the list of elements that compose the signature
        String strElementsList = filterConfig.getInitParameter( PARAMETER_ELEMENTS_SIGNATURE );
        StringTokenizer st = new StringTokenizer( strElementsList, "," );
        List<String> listElements = new ArrayList<String>( );

        while ( st.hasMoreTokens( ) )
        {
            listElements.add( st.nextToken( ).trim( ) );
        }

        _authenticator.setSignatureElements( listElements );

        // Sets The validity Time Period
        String strValidityTimePeriod = filterConfig.getInitParameter( PARAMETER_VALIDITY_PERIOD );
        _authenticator.setValidityTimePeriod( Long.parseLong( strValidityTimePeriod ) );
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain ) throws IOException, ServletException
    {
        if ( _authenticator.isRequestAuthenticated( (HttpServletRequest) request ) )
        {
            chain.doFilter( request, response );
        }
        else
        {
            ( (HttpServletResponse) response ).setStatus( HttpServletResponse.SC_UNAUTHORIZED );
        }
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public void destroy( )
    {
    }
}
