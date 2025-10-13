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

package org.omnione.did.oid4vc.enrollment.core.crypto;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.omnione.did.crypto.enums.MultiBaseType;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.keypair.EcKeyPair;
import org.omnione.did.crypto.util.CryptoUtils;
import org.omnione.did.crypto.util.DigestUtils;
import org.omnione.did.crypto.util.MultiBaseUtils;
import org.omnione.did.data.model.enums.profile.EccCurveType;
import org.omnione.did.data.model.enums.profile.SymmetricCipherType;
import org.omnione.did.oid4vc.enrollment.exception.SdkException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

/**
 * Default implementation of CryptoProvider using OmniOne SDK utilities.
 * This implementation now uses OmniOne CryptoUtils and DigestUtils for server compatibility.
 */
@Slf4j
public class DefaultCryptoProvider implements CryptoProvider {

  private final SecureRandom secureRandom;

  /**
   * Constructor with default SecureRandom.
   */
  public DefaultCryptoProvider() {
    SecureRandom secureRandomTemp;
    try {
      secureRandomTemp = SecureRandom.getInstanceStrong();
    } catch (NoSuchAlgorithmException e) {
      log.warn("Strong SecureRandom not available, using default: {}", e.getMessage());
      secureRandomTemp = new SecureRandom();
    }
    this.secureRandom = secureRandomTemp;
    
    // Add BouncyCastle provider if not already added
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Override
  public EcKeyPair generateKeyPair(EccCurveType curveType) throws SdkException {
    try {
      log.debug("=== Generating Key Pair (OmniOne SDK) ===");
      log.debug("Curve type: {}", curveType);

      // Handle null curve type with default
      if (curveType == null) {
        curveType = EccCurveType.SECP256R1;
        log.debug("Curve type was null, using default: {}", curveType);
      }

      // Convert to OmniOne DidKeyType using the same method as server
      org.omnione.did.crypto.enums.DidKeyType didKeyType = convertToOmnioneDidKeyType(curveType);

      // Use OmniOne CryptoUtils directly (same as server)
      EcKeyPair ecKeyPair = (EcKeyPair) CryptoUtils.generateKeyPair(didKeyType);

      log.debug("=== Key Pair Generation Complete ===");
      return ecKeyPair;

    } catch (CryptoException e) {
      log.error("Failed to generate key pair: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to generate key pair: " + e.getMessage(),
          e
      );
    } catch (Exception e) {
      log.error("Failed to generate key pair: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to generate key pair: " + e.getMessage(),
          e
      );
    }
  }

  /**
   * Convert SDK EccCurveType to OmniOne DidKeyType (same as server)
   */
  private org.omnione.did.crypto.enums.DidKeyType convertToOmnioneDidKeyType(EccCurveType curveType) {
    switch (curveType) {
      case SECP256K1:
        return org.omnione.did.crypto.enums.DidKeyType.SECP256K1_VERIFICATION_KEY_2018;
      case SECP256R1:
      default:
        return org.omnione.did.crypto.enums.DidKeyType.SECP256R1_VERIFICATION_KEY_2018;
    }
  }

  @Override
  public String generateNonce(int lengthInBytes) throws SdkException {
    try {
      log.debug("=== Generating Nonce (CryptoUtils) ===");
      log.debug("Requested nonce length: {} bytes", lengthInBytes);

      // Use CryptoUtils.generateNonce() exactly like server
      byte[] nonceBytes = CryptoUtils.generateNonce(lengthInBytes);
      log.debug("Generated nonce bytes (hex): {}", bytesToHex(nonceBytes));

      // Encode with multibase base58btc (z prefix) - same as server
      String nonce = MultiBaseUtils.encode(nonceBytes, MultiBaseType.base58btc);
      log.debug("Encoded nonce (multibase z): {}", nonce);
      log.debug("=== Nonce Generation Complete ===");

      return nonce;
    } catch (CryptoException e) {
      log.error("Failed to generate nonce: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to generate nonce: " + e.getMessage(),
          e
      );
    } catch (Exception e) {
      log.error("Failed to generate nonce: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to generate nonce: " + e.getMessage(),
          e
      );
    }
  }

  @Override
  public byte[] generateSharedSecret(byte[] compressedPublicKey, byte[] privateKeyBytes, EccCurveType curveType) throws SdkException {
    try {
      log.debug("=== Generating Shared Secret (CryptoUtils) ===");
      log.debug("Public key length: {} bytes", compressedPublicKey.length);
      log.debug("Private key length: {} bytes", privateKeyBytes.length);
      log.debug("Curve type: {}", curveType);

      // Handle null curve type with default
      if (curveType == null) {
        curveType = EccCurveType.SECP256R1;
        log.debug("Curve type was null, using default: {}", curveType);
      }

      // Convert to OmniOne ECC curve type (for generateSharedSecret)
      org.omnione.did.crypto.enums.EccCurveType omnioneCurveType = convertToOmnioneEccCurveType(curveType);

      // Use CryptoUtils.generateSharedSecret() exactly like server
      byte[] sharedSecret = CryptoUtils.generateSharedSecret(compressedPublicKey, privateKeyBytes, omnioneCurveType);

      log.debug("ECDH shared secret generated successfully, length: {} bytes", sharedSecret.length);
      log.debug("Shared secret (hex): {}", bytesToHex(sharedSecret));
      log.debug("=== Shared Secret Generation Complete ===");

      return sharedSecret;

    } catch (CryptoException e) {
      log.error("Failed to generate shared secret: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to generate shared secret: " + e.getMessage(),
          e
      );
    } catch (Exception e) {
      log.error("Failed to generate shared secret: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to generate shared secret: " + e.getMessage(),
          e
      );
    }
  }

  /**
   * Convert SDK EccCurveType to OmniOne EccCurveType (for shared secret generation)
   */
  private org.omnione.did.crypto.enums.EccCurveType convertToOmnioneEccCurveType(EccCurveType curveType) {
    switch (curveType) {
      case SECP256K1:
        return org.omnione.did.crypto.enums.EccCurveType.Secp256k1;
      case SECP256R1:
      default:
        return org.omnione.did.crypto.enums.EccCurveType.Secp256r1;
    }
  }

  @Override
  public byte[] mergeNonce(String clientNonce, String serverNonce) throws SdkException {
    try {
      log.debug("=== Merging Nonces Debug ===");
      log.debug("Client nonce (raw): {}", clientNonce);
      log.debug("Server nonce (raw): {}", serverNonce);

      return DigestUtils.mergeNonce(MultiBaseUtils.decode(clientNonce), MultiBaseUtils.decode(serverNonce));
    } catch (Exception e) {
      log.error("Failed to merge nonces: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to merge nonces: " + e.getMessage(),
          e
      );
    }
  }

  @Override
  public byte[] mergeSharedSecretAndNonce(byte[] sharedSecret, byte[] mergedNonce, SymmetricCipherType cipherType) throws SdkException {
    try {
      log.debug("=== Merging Shared Secret and Nonce Debug ===");
      log.debug("Shared secret length: {} bytes", sharedSecret.length);
      log.debug("Shared secret (hex): {}", bytesToHex(sharedSecret));
      log.debug("Merged nonce length: {} bytes", mergedNonce.length);
      log.debug("Merged nonce (hex): {}", bytesToHex(mergedNonce));
      log.debug("Target cipher type: {}", cipherType);

      // Implementation using standard Java MessageDigest
      MessageDigest digest = MessageDigest.getInstance("SHA-256");

      // Order matters: shared secret first, then nonce
      digest.update(sharedSecret);
      digest.update(mergedNonce);
      byte[] rawKey = digest.digest();

      log.debug("Raw derived key (hex): {}", bytesToHex(rawKey));

      // Truncate key to appropriate length for cipher type
      int keyLength = getKeyLengthForCipher(cipherType);
      byte[] encryptionKey;

      if (rawKey.length > keyLength) {
        encryptionKey = Arrays.copyOf(rawKey, keyLength);
        log.debug("Key truncated from {} to {} bytes", rawKey.length, keyLength);
      } else if (rawKey.length < keyLength) {
        // This shouldn't happen with SHA-256, but handle it just in case
        encryptionKey = new byte[keyLength];
        System.arraycopy(rawKey, 0, encryptionKey, 0, rawKey.length);
        log.debug("Key padded from {} to {} bytes", rawKey.length, keyLength);
      } else {
        encryptionKey = rawKey;
        log.debug("Key length matches exactly: {} bytes", keyLength);
      }

      log.debug("Final encryption key length: {} bytes", encryptionKey.length);
      log.debug("Final encryption key (hex): {}", bytesToHex(encryptionKey));
      log.debug("=== Key Derivation Complete ===");

      return encryptionKey;

    } catch (Exception e) {
      log.error("Failed to merge shared secret and nonce: {}", e.getMessage(), e);
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to merge shared secret and nonce: " + e.getMessage(),
          e
      );
    }
  }

  @Override
  public byte[] decrypt(String encryptedData, byte[] key, String iv, SymmetricCipherType cipherType, String padding) throws SdkException {
    try {
      log.debug("Decrypting data using cipher type: {} with padding: {}", cipherType, padding);

      // Implementation using standard Java crypto
      String transformation = mapCipherTypeToTransformation(cipherType, padding);
      Cipher cipher = Cipher.getInstance(transformation);

      SecretKeySpec keySpec = new SecretKeySpec(key, getAlgorithmName(cipherType));
      byte[] ivBytes = MultiBaseUtils.decode(iv);
      IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

      byte[] encryptedBytes = MultiBaseUtils.decode(encryptedData);
      byte[] decryptedData = cipher.doFinal(encryptedBytes);

      log.debug("Data decrypted successfully");
      return decryptedData;

    } catch (Exception e) {
      e.printStackTrace();
      log.error("Failed to decrypt data: {}", e.getMessage());
      throw new SdkException(
          SdkException.ErrorCodes.CRYPTO_ERROR,
          "Failed to decrypt data: " + e.getMessage(),
          e
      );
    }
  }

  /**
   * Maps SymmetricCipherType to Java Cipher transformation.
   */
  private String mapCipherTypeToTransformation(SymmetricCipherType cipherType, String padding) {
    String algorithm = getAlgorithmName(cipherType);
    String mode;
    
    // Determine mode from cipher type
    switch (cipherType) {
      case AES_128_CBC:
      case AES_256_CBC:
        mode = "CBC";
        break;
      case AES_128_ECB:
      case AES_256_ECB:
        mode = "ECB";
        break;
      default:
        mode = "CBC"; // Default mode
    }
    
    // Handle padding - ensure it's in the correct format
    String paddingStr;
    if (padding == null || padding.isEmpty()) {
      paddingStr = "PKCS5Padding"; // Default padding for AES
    } else if (padding.toLowerCase().contains("pkcs5")) {
      paddingStr = "PKCS5Padding";
    } else if (padding.toLowerCase().contains("pkcs7")) {
      paddingStr = "PKCS5Padding"; // Java uses PKCS5Padding for PKCS7
    } else if (padding.toLowerCase().contains("nopadding")) {
      paddingStr = "NoPadding";
    } else {
      // If padding already ends with "Padding", use as-is, otherwise append "Padding"
      paddingStr = padding.endsWith("Padding") ? padding : padding + "Padding";
    }
    
    String transformation = algorithm + "/" + mode + "/" + paddingStr;
    log.debug("Mapped cipher transformation: {}", transformation);
    return transformation;
  }

  /**
   * Gets the algorithm name for the cipher type.
   */
  private String getAlgorithmName(SymmetricCipherType cipherType) {
    switch (cipherType) {
      case AES_128_CBC:
      case AES_256_CBC:
      case AES_128_ECB:
      case AES_256_ECB:
        return "AES";
      default:
        return "AES"; // Default to AES
    }
  }

  /**
   * Gets the key length in bytes for the cipher type.
   */
  private int getKeyLengthForCipher(SymmetricCipherType cipherType) {
    switch (cipherType) {
      case AES_128_CBC:
      case AES_128_ECB:
        return 16; // 128 bits
      case AES_256_CBC:
      case AES_256_ECB:
        return 32; // 256 bits
      default:
        return 32; // Default to 256 bits
    }
  }

  /**
   * Helper method to convert bytes to hex string for debugging
   */
  private String bytesToHex(byte[] bytes) {
    StringBuilder result = new StringBuilder();
    for (byte b : bytes) {
      result.append(String.format("%02x", b));
    }
    return result.toString();
  }
}