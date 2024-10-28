/*
 * Copyright (c) 2002-2025, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice
 *    and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice
 *    and the following disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
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

import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

/**
 * IPAuthentificator is a class that authenticates requests based on the client's IP address.
 * It can be configured to either allow or block requests from specific IP addresses.
 */
public class IPAuthentificator implements RequestAuthenticator {
	
	/**
	 * Enum representing the mode of operation for the authenticator.
	 * ALLOW: Only requests from the specified IP addresses are allowed.
	 * BLOCK: Requests from the specified IP addresses are blocked.
	 */
	public enum MODE {
		ALLOW,
		BLOCK
	}
	
	private Set<String> _listIPs;
	private MODE _mode;
	
	/**
	 * Gets the list of IP addresses.
	 * 
	 * @return the list of IP addresses
	 */
	public Set<String> getIPs( ) {
		return _listIPs;
	}
	
	/**
	 * Sets the list of IP addresses.
	 * 
	 * @param list
	 * 		The list of IP addresses
	 */
	public void setIPs( Set<String> list ) {
		this._listIPs = list;
	}
	
	/**
	 * Gets the enum value that defines if the IPs in the set will be allowed or denied.
	 * 
	 * @return the enum case (either ALLOW or BLOCK)
	 */
	public MODE getMode( ) {
		return _mode;
	}

	/**
	 * Sets the enum value that defines if the IPs in the set will be allowed or denied.
	 * 
	 * @param mode
	 * 		The enum value of allow or block
	 */
	public void setMode( MODE mode ) {
		this._mode = mode;
	}
	
	/**
	 * {@inheritDoc }
	 * 
	 * Authenticates the request based on the client's IP address.
	 * 
	 * @param request The HTTP request to authenticate
	 * @return true if the request is authenticated, false otherwise
	 */
	@Override
	public boolean isRequestAuthenticated( HttpServletRequest request ) {
		String remoteAddr = request.getRemoteAddr();
		boolean isIPInList = _listIPs != null && _listIPs.contains(remoteAddr);

		switch (_mode) {
			case ALLOW:
				return isIPInList;
			case BLOCK:
				return !isIPInList;
			default:
				return false;
		}
	}

	/**
	 * {@inheritDoc }
	 * 
	 * Gets security information for the request.
	 * 
	 * @param elements The list of elements to include in the security information
	 * @return An instance of AuthenticateRequestInformations containing the security information
	 */
	@Override
	public AuthenticateRequestInformations getSecurityInformations( List<String> elements ) {
		// Implementation not provided
		return null;
	}
}
