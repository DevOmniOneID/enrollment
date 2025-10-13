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

package org.omnione.did.oid4vc.enrollment.core.model;

import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;
import org.omnione.did.data.model.vc.VerifiableCredential;

import java.time.Instant;
import java.util.Map;

/**
 * Response model for entity enrollment.
 * Contains the result of the enrollment process.
 */
@Data
@Builder
@Jacksonized
public class EnrollResponse {
    
    /**
     * Indicates whether the enrollment was successful.
     */
    private boolean success;
    
    /**
     * The transaction ID used throughout the enrollment process.
     */
    private String transactionId;
    
    /**
     * The obtained certificate verifiable credential.
     * Null if enrollment failed.
     */
    private VerifiableCredential certificateVc;
    
    /**
     * The ID of the certificate VC for quick reference.
     */
    private String certificateVcId;
    
    /**
     * Timestamp when the enrollment was completed.
     */
    private Instant completedAt;
    
    /**
     * Duration of the enrollment process in milliseconds.
     */
    private long processingTimeMs;
    
    /**
     * Error code if enrollment failed.
     */
    private String errorCode;
    
    /**
     * Error message if enrollment failed.
     */
    private String errorMessage;
    
    /**
     * Additional response metadata.
     * Can contain debug information or custom data.
     */
    @Builder.Default
    private Map<String, Object> metadata = Map.of();

    /**
     * Creates a successful enrollment response.
     *
     * @param transactionId the transaction ID
     * @param certificateVc the certificate VC
     * @param processingTimeMs the processing time in milliseconds
     * @return a successful EnrollResponse instance
     */
    public static EnrollResponse success(String transactionId, VerifiableCredential certificateVc, long processingTimeMs) {
        return EnrollResponse.builder()
                .success(true)
                .transactionId(transactionId)
                .certificateVc(certificateVc)
                .certificateVcId(certificateVc != null ? certificateVc.getId() : null)
                .completedAt(Instant.now())
                .processingTimeMs(processingTimeMs)
                .build();
    }

    /**
     * Creates a failed enrollment response.
     *
     * @param transactionId the transaction ID (can be null if enrollment failed early)
     * @param errorCode the error code
     * @param errorMessage the error message
     * @param processingTimeMs the processing time in milliseconds
     * @return a failed EnrollResponse instance
     */
    public static EnrollResponse failure(String transactionId, String errorCode, String errorMessage, long processingTimeMs) {
        return EnrollResponse.builder()
                .success(false)
                .transactionId(transactionId)
                .errorCode(errorCode)
                .errorMessage(errorMessage)
                .completedAt(Instant.now())
                .processingTimeMs(processingTimeMs)
                .build();
    }
}