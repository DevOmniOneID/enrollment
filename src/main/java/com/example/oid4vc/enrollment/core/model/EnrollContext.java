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
import org.omnione.did.crypto.keypair.EcKeyPair;
import org.omnione.did.data.model.did.DidDocument;
import org.omnione.did.data.model.enums.profile.EccCurveType;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Context object that holds state information during the enrollment process.
 * This is used internally by the SDK to maintain state across multiple API calls.
 */
@Data
@Builder
@Jacksonized
public class EnrollContext {
    
    /**
     * The original enrollment request.
     */
    private EnrollRequest originalRequest;
    
    /**
     * Transaction ID obtained from propose-enroll-entity.
     */
    private String transactionId;
    
    /**
     * Authentication nonce from TAS.
     */
    private String authNonce;
    
    /**
     * Client-generated nonce for ECDH.
     */
    private String clientNonce;
    
    /**
     * Server nonce received from TAS.
     */
    private String serverNonce;
    
    /**
     * Temporary key pair generated for ECDH.
     */
    private EcKeyPair temporaryKeyPair;
    
    /**
     * The elliptic curve type being used.
     */
    private EccCurveType curveType;
    
    /**
     * DID Document of the entity being enrolled.
     */
    private DidDocument didDocument;
    
    /**
     * Shared secret derived from ECDH.
     */
    private byte[] sharedSecret;
    
    /**
     * Merged nonce for encryption/decryption.
     */
    private byte[] mergedNonce;
    
    /**
     * Final key for encryption/decryption.
     */
    private byte[] encryptionKey;
    
    /**
     * Timestamp when the enrollment process started.
     */
    private Instant startedAt;
    
    /**
     * Current step in the enrollment process.
     */
    @Builder.Default
    private EnrollmentStep currentStep = EnrollmentStep.INITIALIZED;
    
    /**
     * Additional context data for extensions or debugging.
     */
    @Builder.Default
    private Map<String, Object> additionalData = new HashMap<>();

    /**
     * Enumeration of enrollment process steps.
     */
    public enum EnrollmentStep {
        INITIALIZED,
        PROPOSE_SENT,
        ECDH_COMPLETED,
        AUTH_COMPLETED,
        CERTIFICATE_RECEIVED,
        ENROLLMENT_CONFIRMED,
        COMPLETED,
        FAILED
    }
    
    /**
     * Updates the current step and records the timestamp.
     *
     * @param step the new step
     */
    public void updateStep(EnrollmentStep step) {
        EnrollmentStep previousStep = this.currentStep;
        this.currentStep = step;
        this.additionalData.put("stepUpdatedAt", Instant.now());
        this.additionalData.put("previousStep", previousStep);
    }
}