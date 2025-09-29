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

package com.example.oid4vc.enrollment.core.model;

import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;
import org.omnione.did.data.model.enums.profile.EccCurveType;
import org.omnione.did.data.model.enums.profile.SymmetricCipherType;

import java.util.List;
import java.util.Map;

/**
 * Request model for entity enrollment.
 * Contains all necessary information to initiate the enrollment process.
 */
@Data
@Builder
@Jacksonized
public class EnrollRequest {
    
    /**
     * Optional custom message ID for tracking.
     * If not provided, SDK will generate a random ID.
     */
    private String messageId;
    
    /**
     * Custom client nonce for additional security.
     * If not provided, SDK will generate a random nonce.
     */
    private String clientNonce;
    
    /**
     * Preferred elliptic curve type for key operations.
     * Defaults to SECP_256_R1 if not specified.
     */
    @Builder.Default
    private EccCurveType preferredCurveType = EccCurveType.SECP256R1;
    
    /**
     * List of supported cipher types for ECDH.
     * If not provided, all available ciphers will be used.
     */
    private List<SymmetricCipherType> supportedCiphers;
    
    /**
     * Additional metadata for the enrollment request.
     * Can be used for custom extensions or debugging information.
     */
    @Builder.Default
    private Map<String, Object> metadata = Map.of();
    
    /**
     * Timeout for the entire enrollment process in milliseconds.
     * Defaults to 60 seconds.
     */
    @Builder.Default
    private long timeoutMs = 60000L;
    
    /**
     * Whether to save the certificate VC automatically after enrollment.
     * Defaults to true.
     */
    @Builder.Default
    private boolean autoSaveCertificate = true;

    /**
     * Creates a default enrollment request with standard settings.
     *
     * @return a default EnrollRequest instance
     */
    public static EnrollRequest defaultRequest() {
        return EnrollRequest.builder().build();
    }
}