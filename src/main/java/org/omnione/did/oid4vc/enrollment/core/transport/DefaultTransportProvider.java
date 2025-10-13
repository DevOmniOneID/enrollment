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

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.omnione.did.oid4vc.enrollment.config.JacksonConfig;
import org.omnione.did.oid4vc.enrollment.exception.SdkException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of TransportProvider using Java HttpClient.
 * Provides basic HTTP communication capabilities for TAS interaction.
 */
@Slf4j
public class DefaultTransportProvider implements TransportProvider {
    
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String HEADER_ACCEPT = "Accept";
    
    private String baseUrl;
    private int connectionTimeoutMs = 30000;
    private int readTimeoutMs = 30000;
    private Map<String, String> defaultHeaders = new HashMap<>();
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    
    /**
     * Constructor with default settings.
     */
    public DefaultTransportProvider(String baseUrl) {
        this.baseUrl = baseUrl;
        this.objectMapper = JacksonConfig.createObjectMapper();
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        
        // Set default headers
        defaultHeaders.put(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON);
        defaultHeaders.put(HEADER_ACCEPT, CONTENT_TYPE_JSON);
    }
    
    @Override
    public <T> T post(String endpoint, Object request, Class<T> responseType) throws SdkException {
        return post(endpoint, request, Map.of(), responseType);
    }
    
    @Override
    public <T> T post(String endpoint, Object request, Map<String, String> headers, Class<T> responseType) throws SdkException {
        try {
            String url = buildUrl(endpoint);
            String requestBody = objectMapper.writeValueAsString(request);
            
            // Enhanced logging for debugging
            if (log.isDebugEnabled()) {
                log.debug("=== HTTP POST Request ===");
                log.debug("URL: {}", url);
                log.debug("Headers: {}", defaultHeaders);
                if (!headers.isEmpty()) {
                    log.debug("Custom Headers: {}", headers);
                }
                log.debug("Request Body:");
                log.debug("{}", formatJson(requestBody));
                log.debug("========================");
            }
            
            log.info("POST request to: {}", url);
            if (log.isTraceEnabled()) {
                log.trace("Request body: {}", requestBody);
            }
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofMillis(readTimeoutMs))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8));
            
            // Add default headers
            for (Map.Entry<String, String> entry : defaultHeaders.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
            
            // Add custom headers
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
            
            HttpRequest httpRequest = requestBuilder.build();
            
            HttpResponse<String> response = httpClient.send(
                    httpRequest, 
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            
            // Enhanced response logging
            if (log.isDebugEnabled()) {
                log.debug("=== HTTP Response ===");
                log.debug("Status Code: {}", response.statusCode());
                log.debug("Response Headers: {}", response.headers().map());
                log.debug("Response Body:");
                log.debug("{}", formatJson(response.body()));
                log.debug("====================");
            }
            
            log.info("Response status: {}", response.statusCode());
            if (log.isTraceEnabled()) {
                log.trace("Response body: {}", response.body());
            }
            
            if (response.statusCode() >= 400) {
                throw new SdkException(
                        SdkException.ErrorCodes.TRANSPORT_ERROR,
                        String.format("HTTP error %d: %s", response.statusCode(), response.body())
                );
            }
            
            return objectMapper.readValue(response.body(), responseType);
            
        } catch (IOException e) {
            log.error("IO error during POST request to {}: {}", endpoint, e.getMessage());
            throw new SdkException(
                    SdkException.ErrorCodes.TRANSPORT_ERROR,
                    "IO error during HTTP request: " + e.getMessage(),
                    e
            );
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Request interrupted: {}", e.getMessage());
            throw new SdkException(
                    SdkException.ErrorCodes.TRANSPORT_ERROR,
                    "Request interrupted: " + e.getMessage(),
                    e
            );
        } catch (Exception e) {
            log.error("Unexpected error during POST request: {}", e.getMessage());
            throw new SdkException(
                    SdkException.ErrorCodes.TRANSPORT_ERROR,
                    "Unexpected error during HTTP request: " + e.getMessage(),
                    e
            );
        }
    }
    
    @Override
    public void setBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Base URL cannot be null or empty");
        }
        
        this.baseUrl = baseUrl.endsWith("/") ? 
                baseUrl.substring(0, baseUrl.length() - 1) : 
                baseUrl;
        
        log.debug("Base URL set to: {}", this.baseUrl);
    }
    
    @Override
    public void setConnectionTimeout(int timeoutMs) {
        if (timeoutMs <= 0) {
            throw new IllegalArgumentException("Connection timeout must be positive");
        }
        this.connectionTimeoutMs = timeoutMs;
        log.debug("Connection timeout set to: {}ms", timeoutMs);
    }
    
    @Override
    public void setReadTimeout(int timeoutMs) {
        if (timeoutMs <= 0) {
            throw new IllegalArgumentException("Read timeout must be positive");
        }
        this.readTimeoutMs = timeoutMs;
        log.debug("Read timeout set to: {}ms", timeoutMs);
    }
    
    @Override
    public void setDefaultHeaders(Map<String, String> headers) {
        if (headers == null) {
            headers = new HashMap<>();
        }
        
        this.defaultHeaders.clear();
        this.defaultHeaders.putAll(headers);
        
        // Ensure JSON content type headers are always present
        if (!this.defaultHeaders.containsKey(HEADER_CONTENT_TYPE)) {
            this.defaultHeaders.put(HEADER_CONTENT_TYPE, CONTENT_TYPE_JSON);
        }
        if (!this.defaultHeaders.containsKey(HEADER_ACCEPT)) {
            this.defaultHeaders.put(HEADER_ACCEPT, CONTENT_TYPE_JSON);
        }
        
        log.debug("Default headers updated: {}", this.defaultHeaders);
    }
    
    /**
     * Builds the full URL for an endpoint.
     *
     * @param endpoint the endpoint path
     * @return the full URL
     */
    private String buildUrl(String endpoint) {
        if (baseUrl == null) {
            throw new IllegalStateException("Base URL is not set");
        }
        
        String path = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        return baseUrl + path;
    }
    
    @Override
    public <T> T postAdmin(String endpoint, Object request, Class<T> responseType) throws SdkException {
        // 임시로 baseUrl을 admin으로 변경
        String originalBaseUrl = this.baseUrl;
        String adminBaseUrl = buildAdminBaseUrl();
        
        try {
            // Admin 전용 baseUrl로 임시 변경
            this.baseUrl = adminBaseUrl;
            
            // 기존 post 메서드 활용
            return post(endpoint, request, responseType);
            
        } finally {
            // 원래 baseUrl로 복구
            this.baseUrl = originalBaseUrl;
        }
    }
    
    /**
     * Builds admin base URL by replacing /api/ with /admin/ in current baseUrl.
     */
    private String buildAdminBaseUrl() {
        if (baseUrl == null) {
            throw new IllegalStateException("Base URL is not set");
        }
        
        // /tas/api/v1 -> /tas/admin/v1로 변경
        if (baseUrl.contains("/tas/api/")) {
            return baseUrl.replace("/tas/api/", "/tas/admin/");
        }
        
        // 기본적으로 /api/를 /admin/으로 교체
        if (baseUrl.contains("/api/")) {
            return baseUrl.replace("/api/", "/admin/");
        }
        
        // 패턴이 없으면 그대로 반환 (fallback)
        return baseUrl;
    }

    /**
     * Formats JSON string for better readability in logs.
     * If parsing fails, returns the original string.
     *
     * @param jsonString the JSON string to format
     * @return formatted JSON string
     */
    private String formatJson(String jsonString) {
        try {
            Object json = objectMapper.readValue(jsonString, Object.class);
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (Exception e) {
            // If JSON parsing fails, return original string
            return jsonString;
        }
    }
}