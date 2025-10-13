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

package org.omnione.did.oid4vc.enrollment.core.entity;

import lombok.extern.slf4j.Slf4j;
import org.omnione.did.crypto.enums.MultiBaseType;
import org.omnione.did.crypto.util.MultiBaseUtils;
import org.omnione.did.data.model.did.DidDocument;
import org.omnione.did.data.model.did.Proof;
import org.omnione.did.data.model.did.VerificationMethod;
import org.omnione.did.data.model.vc.VerifiableCredential;
import org.omnione.did.oid4vc.enrollment.exception.SdkException;
import org.omnione.did.wallet.key.WalletManagerInterface;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default implementation of EntityProvider.
 * Integrates with WalletManagerInterface for wallet and signature operations.
 *
 * This implementation combines the functionalities of WalletProvider and SignatureProvider
 * into a single cohesive entity management interface.
 */
@Slf4j
public class DefaultEntityProvider implements EntityProvider {

  private static final String DEFAULT_WALLET_ID = "default_wallet";

  private final WalletManagerInterface walletManager;
  private DidDocument didDocument;
  private final Map<String, VerifiableCredential> credentials = new ConcurrentHashMap<>();
  private boolean ready = false;

  /**
   * Constructor with WalletManagerInterface and DID document.
   *
   * @param walletManager the wallet manager interface
   * @param didDocument the DID document for this wallet
   */
  public DefaultEntityProvider(WalletManagerInterface walletManager, DidDocument didDocument) {
    this.walletManager = walletManager;
    if (walletManager == null) {
      throw new IllegalArgumentException("WalletManagerInterface cannot be null");
    }

    this.didDocument = didDocument;
    this.ready = (didDocument != null);

    if (ready) {
      log.info("DefaultEntityProvider initialized with DID: {}", didDocument.getId());
    }
  }

  // ==================== WalletProvider Implementation ====================

  @Override
  public DidDocument getDidDocument() throws SdkException {
    if (!ready) {
      throw new SdkException(
          SdkException.ErrorCodes.WALLET_ERROR,
          "Wallet is not ready. DID document not available."
      );
    }

    if (didDocument == null) {
      throw new SdkException(
          SdkException.ErrorCodes.WALLET_ERROR,
          "No DID document found in wallet"
      );
    }

    log.debug("Retrieved DID document: {}", didDocument.getId());
    return didDocument;
  }

  // ==================== SignatureProvider Implementation ====================

  @Override
  public String signData(DidDocument didDocument, String data, String keyId) throws SdkException {
    try {
      log.info("Signing data with key ID: {}", keyId);
      log.info("=== SignatureProvider Debug ===");
      log.info("Original data to sign: {}", data);

      if (!walletManager.isConnect()) {
        throw new SdkException(
            SdkException.ErrorCodes.SIGNATURE_ERROR,
            "Wallet manager is not connected"
        );
      }

      // Hash the data
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hashedData = digest.digest(data.getBytes(StandardCharsets.UTF_8));

      log.info("SHA-256 hash (hex): {}", bytesToHex(hashedData));
      log.info("SHA-256 hash (base64): {}", Base64.getEncoder().encodeToString(hashedData));

      // Delegate to WalletManagerInterface for signing
      byte[] signature = walletManager.generateCompactSignatureFromHash(keyId, hashedData);

      log.info("Raw signature bytes length: {}", signature.length);
      log.info("Raw signature (base64): {}", Base64.getEncoder().encodeToString(signature));

      // Return Multibase-encoded signature (Base58 with 'z' prefix)
      String multibaseSignature = MultiBaseUtils.encode(signature, MultiBaseType.base58btc);
      log.info("Final multibase signature: {}", multibaseSignature);
      log.info("=== End SignatureProvider Debug ===");

      log.info("Data signed successfully with key ID: {}", keyId);
      return multibaseSignature;

    } catch (SdkException e) {
      throw e;
    } catch (Exception e) {
      log.error("Failed to sign data: {}", e.getMessage());
      throw new SdkException(
          SdkException.ErrorCodes.SIGNATURE_ERROR,
          "Failed to sign data: " + e.getMessage(),
          e
      );
    }
  }

  @Override
  public Proof createProof(DidDocument didDocument, String data, Proof proofTemplate) throws SdkException {
    try {
      log.info("Creating proof for DID: {}", didDocument.getId());

      // Get the key ID from verification method
      String keyId = extractKeyIdFromVerificationMethod(proofTemplate.getVerificationMethod());

      // Sign the data
      String signature = signData(didDocument, data, keyId);

      // Create the complete proof
      Proof proof = new Proof();
      proof.setType(proofTemplate.getType());
      proof.setCreated(proofTemplate.getCreated());
      proof.setVerificationMethod(proofTemplate.getVerificationMethod());
      proof.setProofPurpose(proofTemplate.getProofPurpose());
      proof.setProofValue(signature);

      log.info("Proof created successfully");
      return proof;

    } catch (SdkException e) {
      throw e;
    } catch (Exception e) {
      log.error("Failed to create proof: {}", e.getMessage());
      throw new SdkException(
          SdkException.ErrorCodes.SIGNATURE_ERROR,
          "Failed to create proof: " + e.getMessage(),
          e
      );
    }
  }

  @Override
  public String getVerificationMethod(DidDocument didDocument, String keyPurpose) throws SdkException {
    try {
      log.info("Getting verification method for purpose: {}", keyPurpose);

      VerificationMethod verificationMethod = findVerificationMethodByPurpose(didDocument, keyPurpose);

      if (verificationMethod == null) {
        throw new SdkException(
            SdkException.ErrorCodes.SIGNATURE_ERROR,
            "No verification method found for purpose: " + keyPurpose
        );
      }

      String version = didDocument.getVersionId();
      String verificationMethodUrl = didDocument.getId() +
          "?versionId=" + version +
          "#" + verificationMethod.getId();

      log.info("Verification method URL: {}", verificationMethodUrl);
      return verificationMethodUrl;

    } catch (SdkException e) {
      throw e;
    } catch (Exception e) {
      log.error("Failed to get verification method: {}", e.getMessage());
      throw new SdkException(
          SdkException.ErrorCodes.SIGNATURE_ERROR,
          "Failed to get verification method: " + e.getMessage(),
          e
      );
    }
  }

  // ==================== Private Helper Methods ====================

  /**
   * Converts byte array to hex string for debugging
   */
  private String bytesToHex(byte[] bytes) {
    StringBuilder result = new StringBuilder();
    for (byte b : bytes) {
      result.append(String.format("%02x", b));
    }
    return result.toString();
  }

  /**
   * Extracts the key ID from a verification method URL.
   *
   * @param verificationMethod the verification method URL
   * @return the key ID
   */
  private String extractKeyIdFromVerificationMethod(String verificationMethod) {
    if (verificationMethod == null) {
      throw new IllegalArgumentException("Verification method cannot be null");
    }

    // Extract key ID from URL format: did:example:123?versionId=1#keyId
    int hashIndex = verificationMethod.indexOf('#');
    if (hashIndex != -1 && hashIndex < verificationMethod.length() - 1) {
      return verificationMethod.substring(hashIndex + 1);
    }

    throw new IllegalArgumentException("Invalid verification method format: " + verificationMethod);
  }

  /**
   * Finds a verification method by purpose using basic DID document structure.
   * This is a simplified implementation that doesn't rely on DidUtil.
   *
   * @param didDocument the DID document
   * @param keyPurpose the key purpose
   * @return the verification method, or null if not found
   */
  private VerificationMethod findVerificationMethodByPurpose(DidDocument didDocument, String keyPurpose) {
    if (didDocument == null || didDocument.getVerificationMethod() == null) {
      return null;
    }

    String targetKeyId = mapKeyPurposeToKeyId(keyPurpose);

    // Search in verificationMethod array
    List<VerificationMethod> verificationMethods = didDocument.getVerificationMethod();
    for (VerificationMethod vm : verificationMethods) {
      if (vm.getId() != null && vm.getId().contains(targetKeyId)) {
        log.info("Found verification method: {} for purpose: {}", vm.getId(), keyPurpose);
        return vm;
      }
    }

    // If not found by ID pattern, try to find by purpose in different arrays
    VerificationMethod vmByPurpose = findInPurposeArrays(didDocument, targetKeyId);
    if (vmByPurpose != null) {
      return vmByPurpose;
    }

    log.info("No verification method found for purpose: {}", keyPurpose);
    return null;
  }

  /**
   * Searches for verification method in purpose-specific arrays.
   *
   * @param didDocument the DID document
   * @param targetKeyId the target key ID pattern
   * @return the verification method, or null if not found
   */
  private VerificationMethod findInPurposeArrays(DidDocument didDocument, String targetKeyId) {
    // Check authentication array
    if (didDocument.getAuthentication() != null) {
      for (Object auth : didDocument.getAuthentication()) {
        VerificationMethod vm = resolveVerificationMethodReference(didDocument, auth, targetKeyId);
        if (vm != null) return vm;
      }
    }

    // Check assertionMethod array
    if (didDocument.getAssertionMethod() != null) {
      for (Object assertion : didDocument.getAssertionMethod()) {
        VerificationMethod vm = resolveVerificationMethodReference(didDocument, assertion, targetKeyId);
        if (vm != null) return vm;
      }
    }

    // Check keyAgreement array
    if (didDocument.getKeyAgreement() != null) {
      for (Object keyAgree : didDocument.getKeyAgreement()) {
        VerificationMethod vm = resolveVerificationMethodReference(didDocument, keyAgree, targetKeyId);
        if (vm != null) return vm;
      }
    }

    // Check capabilityInvocation array
    if (didDocument.getCapabilityInvocation() != null) {
      for (Object invoke : didDocument.getCapabilityInvocation()) {
        VerificationMethod vm = resolveVerificationMethodReference(didDocument, invoke, targetKeyId);
        if (vm != null) return vm;
      }
    }

    // Check capabilityDelegation array
    if (didDocument.getCapabilityDelegation() != null) {
      for (Object delegate : didDocument.getCapabilityDelegation()) {
        VerificationMethod vm = resolveVerificationMethodReference(didDocument, delegate, targetKeyId);
        if (vm != null) return vm;
      }
    }

    return null;
  }

  /**
   * Resolves a verification method reference to actual VerificationMethod object.
   *
   * @param didDocument the DID document
   * @param reference the reference (can be string ID or embedded object)
   * @param targetKeyId the target key ID pattern
   * @return the verification method, or null if not found or not matching
   */
  private VerificationMethod resolveVerificationMethodReference(DidDocument didDocument, Object reference, String targetKeyId) {
    if (reference == null) {
      return null;
    }

    // If it's a string reference, find the corresponding verification method
    if (reference instanceof String) {
      String refId = (String) reference;
      if (refId.contains(targetKeyId)) {
        // Find the actual verification method by ID
        for (VerificationMethod vm : didDocument.getVerificationMethod()) {
          if (refId.equals(vm.getId()) || refId.endsWith("#" + vm.getId())) {
            return vm;
          }
        }
      }
    }

    // If it's an embedded verification method object
    if (reference instanceof VerificationMethod) {
      VerificationMethod vm = (VerificationMethod) reference;
      if (vm.getId() != null && vm.getId().contains(targetKeyId)) {
        return vm;
      }
    }

    return null;
  }

  /**
   * Maps key purpose to key ID format.
   *
   * @param keyPurpose the key purpose
   * @return the key ID format
   */
  private String mapKeyPurposeToKeyId(String keyPurpose) {
    switch (keyPurpose.toLowerCase()) {
      case "authentication":
        return "auth";
      case "keyagreement":
      case "key_agreement":
        return "keyagree";
      case "assertionmethod":
      case "assertion_method":
        return "assert";
      case "capabilityinvocation":
      case "capability_invocation":
        return "invoke";
      case "capabilitydelegation":
      case "capability_delegation":
        return "delegate";
      default:
        return keyPurpose;
    }
  }
}