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

package org.omnione.did.oid4vc.enrollment.core.enroll;

import org.omnione.did.data.model.did.DidDocument;
import org.omnione.did.data.model.enums.vc.RoleType;
import org.omnione.did.oid4vc.enrollment.core.model.EnrollRequest;
import org.omnione.did.oid4vc.enrollment.core.model.EnrollResponse;
import org.omnione.did.oid4vc.enrollment.exception.SdkException;

/**
 * Main interface for entity enrollment SDK.
 * Provides both synchronous and asynchronous enrollment capabilities.
 */
public interface EnrollEntitySDK {

    /**
     * Enrolls an entity synchronously using default settings.
     *
     * @return the enrollment response
     * @throws SdkException if enrollment fails
     */
    EnrollResponse enrollEntity() throws SdkException;

    /**
     * Enrolls an entity synchronously with custom request parameters.
     *
     * @param request the enrollment request with custom parameters
     * @return the enrollment response
     * @throws SdkException if enrollment fails
     */
    EnrollResponse enrollEntity(EnrollRequest request) throws SdkException;

    /**
     * Registers a DID document to TAS.
     *
     * @param didDocument the DID document
     * @param entityName the entity name
     * @param serverUrl the entity server URL
     * @param certificateUrl the entity certificate URL
     * @param roleType the role type (e.g., "OP_PROVIDER")
     * @throws SdkException if registration fails
     */
    void registerDidToTas(DidDocument didDocument, String entityName, String serverUrl, String certificateUrl, RoleType roleType) throws SdkException;
}