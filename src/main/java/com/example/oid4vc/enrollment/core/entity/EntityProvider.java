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

package com.example.oid4vc.enrollment.core.entity;

import org.omnione.did.data.model.did.DidDocument;
import org.omnione.did.data.model.did.Proof;
import com.example.oid4vc.enrollment.exception.SdkException;

/**
 * Unified interface for entity operations combining wallet and signature functionalities.
 * Provides abstraction for DID document management and digital signature operations.
 */
public interface EntityProvider {

  // ==================== From WalletProvider ====================

  /**
   * Retrieves the DID document of the entity.
   *
   * @return the DID document
   * @throws SdkException if the DID document cannot be retrieved
   */
  DidDocument getDidDocument() throws SdkException;

  // ==================== From SignatureProvider ====================

  /**
   * Signs data and returns the signature as a Multibase encoded string.
   *
   * @param didDocument the DID document containing the signing key
   * @param data the data to sign (typically JSON string)
   * @param keyId the key ID to use for signing
   * @return the signature as Multibase encoded string (Base58 with 'z' prefix)
   * @throws SdkException if signing fails
   */
  String signData(DidDocument didDocument, String data, String keyId) throws SdkException;

  /**
   * Creates a proof object with signature for the given data.
   *
   * @param didDocument the DID document
   * @param data the data to sign (typically serialized JSON)
   * @param proofTemplate the proof template (without proofValue)
   * @return the completed proof with signature
   * @throws SdkException if proof generation fails
   */
  Proof createProof(DidDocument didDocument, String data, Proof proofTemplate) throws SdkException;

  /**
   * Gets the verification method URL for a specific key purpose.
   *
   * @param didDocument the DID document
   * @param keyPurpose the key purpose (authentication, keyAgreement, etc.)
   * @return the verification method URL
   * @throws SdkException if the key is not found
   */
  String getVerificationMethod(DidDocument didDocument, String keyPurpose) throws SdkException;
}