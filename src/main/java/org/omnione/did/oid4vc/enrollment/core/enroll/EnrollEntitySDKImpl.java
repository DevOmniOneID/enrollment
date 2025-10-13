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

import org.omnione.did.oid4vc.enrollment.config.JacksonConfig;
import org.omnione.did.oid4vc.enrollment.core.model.EnrollContext;
import org.omnione.did.oid4vc.enrollment.core.model.EnrollRequest;
import org.omnione.did.oid4vc.enrollment.core.model.EnrollResponse;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.omnione.did.common.util.JsonUtil;
import org.omnione.did.crypto.enums.MultiBaseType;
import org.omnione.did.crypto.keypair.EcKeyPair;
import org.omnione.did.crypto.util.MultiBaseUtils;
import org.omnione.did.data.model.did.DidDocument;
import org.omnione.did.data.model.did.Proof;
import org.omnione.did.data.model.enums.did.ProofType;
import org.omnione.did.data.model.enums.profile.SymmetricCipherType;
import org.omnione.did.data.model.enums.vc.RoleType;
import org.omnione.did.data.model.vc.VerifiableCredential;
import org.omnione.did.oid4vc.enrollment.core.crypto.CryptoProvider;
import org.omnione.did.oid4vc.enrollment.core.entity.EntityProvider;
import org.omnione.did.oid4vc.enrollment.core.model.*;
import org.omnione.did.oid4vc.enrollment.core.transport.TransportProvider;
import org.omnione.did.oid4vc.enrollment.exception.SdkException;

import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Implementation of EnrollEntitySDK interface.
 * Handles the complete entity enrollment process with TAS.
 */
@Slf4j
public class EnrollEntitySDKImpl implements EnrollEntitySDK {

  private final TransportProvider transportProvider;
  private final CryptoProvider cryptoProvider;
  private final EntityProvider entityProvider;
  private EnrollEntityConfig config;

  /**
   * Constructor for dependency injection.
   *
   * @param transportProvider the transport provider
   * @param cryptoProvider the crypto provider
   * @param entityProvider the entity provider
   * @param config the configuration
   */
  public EnrollEntitySDKImpl(
      TransportProvider transportProvider,
      CryptoProvider cryptoProvider,
      EntityProvider entityProvider,
      EnrollEntityConfig config) {

    this.transportProvider = transportProvider;
    this.cryptoProvider = cryptoProvider;
    this.entityProvider = entityProvider;
    this.config = config;

    // Initialize transport provider
    initializeTransportProvider();

    // Validate configuration
    config.validate();

    log.info("EnrollEntitySDK initialized with TAS URL: {}", config.getTasApiBasePath());
  }

  private void initializeTransportProvider() {
    transportProvider.setBaseUrl(config.getTasApiBasePath());
    transportProvider.setConnectionTimeout(config.getConnectionTimeoutMs());
    transportProvider.setReadTimeout(config.getReadTimeoutMs());
    transportProvider.setDefaultHeaders(config.getCustomHeaders());
  }

  /**
   * Converts cipher string to SymmetricCipherType enum.
   */
  private SymmetricCipherType convertCipherStringToType(String cipherStr) throws SdkException {
    if (cipherStr == null) {
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Cipher string cannot be null"
      );
    }
    
    // Convert server cipher string to enum
    switch (cipherStr.toUpperCase().replace("-", "_")) {
      case "AES_128_CBC":
        return SymmetricCipherType.AES_128_CBC;
      case "AES_128_ECB":
        return SymmetricCipherType.AES_128_ECB;
      case "AES_256_CBC":
        return SymmetricCipherType.AES_256_CBC;
      case "AES_256_ECB":
        return SymmetricCipherType.AES_256_ECB;
      default:
        throw new SdkException(
            SdkException.ErrorCodes.CRYPTO_ERROR,
            "Unsupported cipher type from server: " + cipherStr
        );
    }
  }

  @Override
  public EnrollResponse enrollEntity() throws SdkException {
    return enrollEntity(EnrollRequest.defaultRequest());
  }

  @Override
  public EnrollResponse enrollEntity(EnrollRequest request) throws SdkException {
    long startTime = System.currentTimeMillis();
    String transactionId = null;

    try {
      log.info("=== Starting entity enrollment ===");

      // Create enrollment context
      EnrollContext context = createEnrollmentContext(request);
      transactionId = context.getTransactionId();

      // Step 1: Propose enrollment
      log.debug("Step 1: Sending propose-enroll-entity");
      context.updateStep(EnrollContext.EnrollmentStep.PROPOSE_SENT);
      sendProposeEnrollEntity(context);

      // Step 2: ECDH key exchange
      log.debug("Step 2: Performing ECDH key exchange");
      performEcdhKeyExchange(context);
      context.updateStep(EnrollContext.EnrollmentStep.ECDH_COMPLETED);

      // Step 3: Send enrollment request with DID Auth
      log.debug("Step 3: Sending enrollment request with DID Auth");
      performDidAuthentication(context);
      context.updateStep(EnrollContext.EnrollmentStep.AUTH_COMPLETED);

      // Step 4: Decrypt and process certificate VC
      log.debug("Step 4: Processing certificate VC");
      VerifiableCredential certificateVc = decryptCertificateVc(context);
      context.updateStep(EnrollContext.EnrollmentStep.CERTIFICATE_RECEIVED);

      // Step 5: Confirm enrollment
      log.debug("Step 5: Confirming enrollment");
      confirmEnrollment(context, certificateVc.getId());

      context.updateStep(EnrollContext.EnrollmentStep.COMPLETED);

      long processingTime = System.currentTimeMillis() - startTime;
      log.info("*** Entity enrollment completed successfully in {}ms ***", processingTime);

      return EnrollResponse.success(transactionId, certificateVc, processingTime);

    } catch (Exception e) {
      long processingTime = System.currentTimeMillis() - startTime;
      log.error("Entity enrollment failed: {}", e.getMessage(), e);

      String errorCode = (e instanceof SdkException) ?
          ((SdkException) e).getErrorCode() :
          SdkException.ErrorCodes.ENROLL_FAILED;

      return EnrollResponse.failure(transactionId, errorCode, e.getMessage(), processingTime);
    }
  }

  private EnrollContext createEnrollmentContext(EnrollRequest request) throws SdkException {
    String clientNonce = request.getClientNonce() != null ?
        request.getClientNonce() :
        cryptoProvider.generateNonce(config.getNonceLength());

    return EnrollContext.builder()
        .originalRequest(request)
        .clientNonce(clientNonce)
        .curveType(request.getPreferredCurveType())
        .didDocument(entityProvider.getDidDocument())
        .startedAt(Instant.now())
        .build();
  }

  private void sendProposeEnrollEntity(EnrollContext context) throws SdkException {
    ProposeEnrollEntityRequest request = ProposeEnrollEntityRequest.builder()
        .id(generateMessageId())
        .build();

    ProposeEnrollEntityResponse response = transportProvider.post(
        "/propose-enroll-entity",
        request,
        ProposeEnrollEntityResponse.class
    );

    context.setTransactionId(response.getTxId());
    context.setAuthNonce(response.getAuthNonce());
  }

  private void performEcdhKeyExchange(EnrollContext context) throws SdkException {
    // Generate temporary key pair
    EcKeyPair keyPair = cryptoProvider.generateKeyPair(context.getCurveType());
    context.setTemporaryKeyPair(keyPair);

    // Create ECDH request
    EcdhRequest ecdhRequest = createEcdhRequest(context);

    RequestEcdhRequest request = RequestEcdhRequest.builder()
        .id(generateMessageId())
        .txId(context.getTransactionId())
        .reqEcdh(ecdhRequest)
        .build();

    RequestEcdhResponse response = transportProvider.post(
        "/request-ecdh",
        request,
        RequestEcdhResponse.class
    );

    // Process ECDH response
    processEcdhResponse(context, response);
  }

  private EcdhRequest createEcdhRequest(EnrollContext context) throws SdkException {
    try {
      // Create candidate ciphers
      CandidateInfo candidate = CandidateInfo.builder()
          .ciphers(config.getSupportedCiphers())
          .build();

      // Create proof template
      Proof proof = new Proof();
      proof.setType(ProofType.SECP256R1_SIGNATURE_2018.getRawValue());
      proof.setProofPurpose("keyAgreement");
      proof.setCreated(getCurrentUTCTimeString());
      proof.setVerificationMethod(entityProvider.getVerificationMethod(
          context.getDidDocument(),
          "keyAgreement"
      ));

      // Create ECDH request data
      EcdhRequest ecdhRequest = EcdhRequest.builder()
          .client(context.getDidDocument().getId())
          .clientNonce(context.getClientNonce())
          .curve(context.getCurveType())
          .publicKey(context.getTemporaryKeyPair().getBase58CompreessPubKey())
          .candidate(candidate)
          .proof(proof)
          .build();

      log.debug("Temporary public key: {}", MultiBaseUtils.decode(context.getTemporaryKeyPair().getBase58CompreessPubKey()));

      // Sign the request - Server compatible approach
      log.debug("=== Server-compatible Proof Generation Process ===");
      log.debug("Original ecdhRequest (toString): {}", ecdhRequest);
      
      // Server approach: Remove proofValue only (set to null), keep rest of proof structure
      Proof proofWithoutValue = new Proof();
      proofWithoutValue.setType(proof.getType());
      proofWithoutValue.setCreated(proof.getCreated());
      proofWithoutValue.setVerificationMethod(proof.getVerificationMethod());
      proofWithoutValue.setProofPurpose(proof.getProofPurpose());
      proofWithoutValue.setProofValue(null);  // proofValue = null (removed)

      EcdhRequest requestWithoutProofValue = EcdhRequest.builder()
          .candidate(ecdhRequest.getCandidate())
          .client(ecdhRequest.getClient())
          .clientNonce(ecdhRequest.getClientNonce())
          .curve(ecdhRequest.getCurve())
          .publicKey(context.getTemporaryKeyPair().getBase58CompreessPubKey())
          .proof(proofWithoutValue)
          .build();

      // Serialize to canonical JSON (same as server: JsonUtil.serializeAndSort)
      String canonicalJson = JsonUtil.serializeAndSort(requestWithoutProofValue);
      log.debug("Server-compatible canonical JSON: {}", canonicalJson);
      
      // Create proof using the canonical JSON (server hashes this inside signatureProvider)
      Proof signedProof = entityProvider.createProof(
          context.getDidDocument(),
          canonicalJson,
          proof
      );

      // Set the generated proof to the original request
      ecdhRequest.setProof(signedProof);
      
      log.debug("Server-compatible proof generated successfully");
      log.debug("=== End Proof Generation ===");
      return ecdhRequest;

    } catch (Exception e) {
      e.printStackTrace();
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to create ECDH request",
          e
      );
    }
  }

  private void processEcdhResponse(EnrollContext context, RequestEcdhResponse response) throws SdkException {
    try {
      AcceptedEcdh accEcdh = response.getAccEcdh();
      context.setServerNonce(accEcdh.getServerNonce());

      // Convert cipher string to SymmetricCipherType
      SymmetricCipherType serverCipher = convertCipherStringToType(accEcdh.getCipher());
      
      // Store server-selected cipher and padding for decryption
      context.getAdditionalData().put("serverCipher", serverCipher);
      context.getAdditionalData().put("serverPadding", accEcdh.getPadding());

      log.debug("Server selected cipher: {}", serverCipher);
      log.debug("Server selected padding: {}", accEcdh.getPadding());

      // Generate shared secret - delegate to CryptoProvider to handle Base64 decoding
      String compressedPublicKeyStr = accEcdh.getPublicKey();
      byte[] privateKeyBytes = ((ECPrivateKey) context.getTemporaryKeyPair().getPrivateKey()).getEncoded();

      // Use CryptoProvider which should handle the Base64 decoding internally
      // For now, we'll use a simple Base64 decode as fallback
      byte[] compressedPublicKey;
      try {
        compressedPublicKey = MultiBaseUtils.decode(compressedPublicKeyStr);
      } catch (IllegalArgumentException e) {
        // If that fails, it might be in a different format
        throw new SdkException(
            SdkException.ErrorCodes.CRYPTO_ERROR,
            "Cannot decode compressed public key. Expected Base64 format but got: " + compressedPublicKeyStr
        );
      }

      byte[] sharedSecret = cryptoProvider.generateSharedSecret(
          compressedPublicKey,
          privateKeyBytes,
          context.getCurveType()
      );
      context.setSharedSecret(sharedSecret);

      // Merge nonces
      byte[] mergedNonce = cryptoProvider.mergeNonce(
          context.getClientNonce(),
          context.getServerNonce()
      );
      context.setMergedNonce(mergedNonce);

      // Generate encryption key using server-selected cipher
      byte[] encryptionKey = cryptoProvider.mergeSharedSecretAndNonce(
          sharedSecret,
          mergedNonce,
          serverCipher
      );
      context.setEncryptionKey(encryptionKey);

    } catch (Exception e) {
      e.printStackTrace();
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to process ECDH response",
          e
      );
    }
  }

  private void performDidAuthentication(EnrollContext context) throws SdkException {
    try {
      // Create DID Auth object
      DidAuthRequest didAuth = createDidAuth(context);

      RequestEnrollEntityRequest request = RequestEnrollEntityRequest.builder()
          .id(generateMessageId())
          .txId(context.getTransactionId())
          .didAuth(didAuth)
          .build();

      RequestEnrollEntityResponse response = transportProvider.post(
          "/request-enroll-entity",
          request,
          RequestEnrollEntityResponse.class
      );

      // Store encrypted VC info for decryption
      context.getAdditionalData().put("encVc", response.getEncVc());
      context.getAdditionalData().put("iv", response.getIv());

    } catch (Exception e) {
      e.printStackTrace();
      throw new SdkException(
          SdkException.ErrorCodes.SIGNATURE_ERROR,
          "Failed to perform DID authentication",
          e
      );
    }
  }

  private DidAuthRequest createDidAuth(EnrollContext context) throws SdkException {
    try {
      // Create proof template
      Proof proof = new Proof();
      proof.setType(ProofType.SECP256R1_SIGNATURE_2018.getRawValue());
      proof.setProofPurpose("authentication");
      proof.setCreated(getCurrentUTCTimeString());
      proof.setVerificationMethod(entityProvider.getVerificationMethod(
          context.getDidDocument(),
          "authentication"
      ));

      // Create DID Auth object
      DidAuthRequest didAuth = DidAuthRequest.builder()
          .authNonce(context.getAuthNonce())
          .did(context.getDidDocument().getId())
          .proof(proof)
          .build();

      // Sign the DID Auth - Server compatible approach
      
      // Server approach: Remove proofValue only (set to null), keep rest of proof structure
      Proof proofWithoutValue = new Proof();
      proofWithoutValue.setType(proof.getType());
      proofWithoutValue.setCreated(proof.getCreated());
      proofWithoutValue.setVerificationMethod(proof.getVerificationMethod());
      proofWithoutValue.setProofPurpose(proof.getProofPurpose());
      proofWithoutValue.setProofValue(null);  // proofValue = null (removed)
      
      DidAuthRequest didAuthWithoutProofValue = DidAuthRequest.builder()
          .authNonce(didAuth.getAuthNonce())
          .did(didAuth.getDid())
          .proof(proofWithoutValue)
          .build();
      
      // Serialize to canonical JSON (same as server approach)
      String canonicalJson = JsonUtil.serializeAndSort(didAuthWithoutProofValue);
      log.debug("DID Auth - Server-compatible canonical JSON: {}", canonicalJson);
      
      // Create proof using the canonical JSON
      Proof signedProof = entityProvider.createProof(
          context.getDidDocument(),
          canonicalJson,
          proof
      );

      // Set the generated proof to the original request
      didAuth.setProof(signedProof);
      return didAuth;

    } catch (Exception e) {
      throw new SdkException(
          SdkException.ErrorCodes.SIGNATURE_ERROR,
          "Failed to create DID Auth",
          e
      );
    }
  }

  private VerifiableCredential decryptCertificateVc(EnrollContext context) throws SdkException {
    try {
      String encVc = (String) context.getAdditionalData().get("encVc");
      String iv = (String) context.getAdditionalData().get("iv");
      
      // Use server-selected cipher instead of client preference
      SymmetricCipherType serverCipher = (SymmetricCipherType) context.getAdditionalData().get("serverCipher");
      String serverPadding = (String) context.getAdditionalData().get("serverPadding");

      if (serverCipher == null) {
        throw new SdkException(
            SdkException.ErrorCodes.CRYPTO_ERROR,
            "Server cipher type not found in context"
        );
      }

      if (serverPadding == null) {
        serverPadding = "PKCS5Padding"; // Default padding
      }

      log.debug("Using server-selected cipher: {}", serverCipher);
      log.debug("Using server-selected padding: {}", serverPadding);

      byte[] decryptedData = cryptoProvider.decrypt(
          encVc,
          context.getEncryptionKey(),
          iv,
          serverCipher, // Use server-selected cipher
          serverPadding // Use server-selected padding
      );

      String vcJson = new String(decryptedData);

      VerifiableCredential vc = new VerifiableCredential();
      vc.fromJson(vcJson);

      return vc;

    } catch (Exception e) {
      e.printStackTrace();
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to decrypt certificate VC",
          e
      );
    }
  }

  private void confirmEnrollment(EnrollContext context, String vcId) throws SdkException {
    ConfirmEnrollEntityRequest request = ConfirmEnrollEntityRequest.builder()
        .id(generateMessageId())
        .txId(context.getTransactionId())
        .vcId(vcId)
        .build();

    transportProvider.post(
        "/confirm-enroll-entity",
        request,
        ConfirmEnrollEntityResponse.class
    );

    context.updateStep(EnrollContext.EnrollmentStep.ENROLLMENT_CONFIRMED);
  }

  /**
   * Generates a unique message ID combining timestamp and UUID.
   * Format: {timestamp}_{uuid_short}
   * Example: 1727676345123_550e8400
   *
   * @return a unique message ID
   */
  private String generateMessageId() {
    long timestamp = System.currentTimeMillis();
    String shortUuid = UUID.randomUUID().toString().substring(0, 8);
    return timestamp + "_" + shortUuid;
  }

  /**
   * Gets current UTC time string in ISO format.
   * Replaces DateTimeUtil.getCurrentUTCTimeString().
   */
  private String getCurrentUTCTimeString() {
    return Instant.now()
        .atOffset(ZoneOffset.UTC)
        .format(DateTimeFormatter.ISO_INSTANT);
  }

  /**
   * Helper method to convert bytes to hex string for debugging
   */
  private String bytesToHex(byte[] bytes) {
    if (bytes == null) return "null";
    StringBuilder result = new StringBuilder();
    for (byte b : bytes) {
      result.append(String.format("%02x", b));
    }
    return result.toString();
  }

  @Override
  public void registerDidToTas(DidDocument didDocument, String entityName, String serverUrl, String certificateUrl, RoleType roleType) throws SdkException {
    log.info("Starting DID registration to TAS for entity: {}", entityName);
    
    try {
      // DidDocument 객체를 JSON 문자열로 변환
      String didDocJson = didDocument.toJson();

      // Multibase 인코딩 (Base58 사용)
      String encodedDidDocument = MultiBaseUtils.encode(didDocJson.getBytes(StandardCharsets.UTF_8), MultiBaseType.base58btc);

      // 요청 생성
      RegisterDidToTaRequest request = RegisterDidToTaRequest.builder()
          .didDoc(encodedDidDocument)
          .name(entityName)
          .serverUrl(serverUrl)
          .certificateUrl(certificateUrl)
          .role(roleType.name())
          .build();
      
      // TAS에 전송 (admin endpoint 사용)
      String endpoint = "/entities/register-did/public";
      EmptyResponse response = transportProvider.postAdmin(endpoint, request, EmptyResponse.class);
      
      log.info("Successfully registered DID to TAS for entity: {}", entityName);
      
    } catch (Exception e) {
      log.error("Failed to register DID to TAS for entity: {}", entityName, e);
      throw new SdkException(
          SdkException.ErrorCodes.TRANSPORT_ERROR,
          "Failed to register DID to TAS: " + e.getMessage(),
          e
      );
    }
  }
  // Inner classes for API request/response models

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class ProposeEnrollEntityRequest {
    private String id;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class ProposeEnrollEntityResponse {
    private String txId;
    private String authNonce;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class RequestEcdhRequest {
    private String id;
    private String txId;
    private EcdhRequest reqEcdh;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class RequestEcdhResponse {
    private AcceptedEcdh accEcdh;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class EcdhRequest {
    private CandidateInfo candidate;  // candidate가 첫 번째 (알파벳 순)
    private String client;
    private String clientNonce;
    
    @com.fasterxml.jackson.databind.annotation.JsonSerialize(using = JacksonConfig.EccCurveTypeSerializer.class)
    private org.omnione.did.data.model.enums.profile.EccCurveType curve;
    
    private String publicKey;
    private Proof proof;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class CandidateInfo {
    @com.fasterxml.jackson.databind.annotation.JsonSerialize(contentUsing = JacksonConfig.RawValueEnumSerializer.class)
    private java.util.List<org.omnione.did.data.model.enums.profile.SymmetricCipherType> ciphers;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class AcceptedEcdh {
    private String server;
    private String serverNonce;
    private String publicKey;
    private String cipher;
    private String padding;
    private org.omnione.did.data.model.did.Proof proof;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class RequestEnrollEntityRequest {
    private String id;
    private String txId;
    private DidAuthRequest didAuth;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class RequestEnrollEntityResponse {
    private String encVc;
    private String iv;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class DidAuthRequest {
    private String authNonce;
    private String did;
    private Proof proof;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class ConfirmEnrollEntityRequest {
    private String id;
    private String txId;
    private String vcId;
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class ConfirmEnrollEntityResponse {
    // Response fields if needed
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class RegisterDidToTaRequest {
    private String didDoc;           // Multibase로 인코딩된 DID Document
    private String name;             // 엔티티 이름
    private String serverUrl;        // 서버 URL
    private String certificateUrl;   // 인증서 URL
    private String role;             // 역할 타입
  }

  @lombok.Data
  @lombok.Builder
  @lombok.extern.jackson.Jacksonized
  private static class EmptyResponse {
    // 빈 응답
  }
}