/*
 * Copyright 2025 OmniOne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.omnione.did.oid4vc.enrollment.core.transport;

import org.omnione.did.oid4vc.enrollment.exception.SdkException;

import java.util.Map;

/**
 * Interface for transport layer abstraction.
 * Handles HTTP communication with the TAS service.
 */
public interface TransportProvider {
    
    /**
     * Sends a POST request to the specified endpoint.
     *
     * @param endpoint the API endpoint (relative path)
     * @param request the request object to send
     * @param responseType the expected response type
     * @param <T> the response type
     * @return the response object
     * @throws SdkException if the request fails
     */
    <T> T post(String endpoint, Object request, Class<T> responseType) throws SdkException;
    
    /**
     * Sends a POST request with custom headers.
     *
     * @param endpoint the API endpoint (relative path)
     * @param request the request object to send
     * @param headers custom headers to include
     * @param responseType the expected response type
     * @param <T> the response type
     * @return the response object
     * @throws SdkException if the request fails
     */
    <T> T post(String endpoint, Object request, Map<String, String> headers, Class<T> responseType) throws SdkException;
    

    /**
     * Sets the base URL for all requests.
     *
     * @param baseUrl the base URL
     */
    void setBaseUrl(String baseUrl);
    
    /**
     * Sets the connection timeout in milliseconds.
     *
     * @param timeoutMs the timeout in milliseconds
     */
    void setConnectionTimeout(int timeoutMs);
    
    /**
     * Sets the read timeout in milliseconds.
     *
     * @param timeoutMs the timeout in milliseconds
     */
    void setReadTimeout(int timeoutMs);
    
    /**
     * Sets default headers to be included in all requests.
     *
     * @param headers the default headers
     */
    void setDefaultHeaders(Map<String, String> headers);
    
    /**
     * Makes a POST request to TAS admin endpoint.
     * Admin endpoints use /tas/admin/v1 instead of /tas/api/v1.
     *
     * @param endpoint the admin endpoint (without /tas/admin/v1 prefix)
     * @param request the request object
     * @param responseType the expected response type
     * @param <T> the response type
     * @return the response object
     * @throws SdkException if the request fails
     */
    <T> T postAdmin(String endpoint, Object request, Class<T> responseType) throws SdkException;
}