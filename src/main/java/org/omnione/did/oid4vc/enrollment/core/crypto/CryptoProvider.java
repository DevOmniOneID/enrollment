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

import org.omnione.did.crypto.keypair.EcKeyPair;
import org.omnione.did.data.model.enums.profile.EccCurveType;
import org.omnione.did.data.model.enums.profile.SymmetricCipherType;
import org.omnione.did.oid4vc.enrollment.exception.SdkException;

/**
 * Interface for cryptographic operations.
 * Provides abstraction for various crypto operations needed during enrollment.
 */
public interface CryptoProvider {
    
    /**
     * Generates an elliptic curve key pair.
     *
     * @param curveType the elliptic curve type
     * @return the generated key pair
     * @throws SdkException if key generation fails
     */
    EcKeyPair generateKeyPair(EccCurveType curveType) throws SdkException;
    
    /**
     * Generates a random nonce.
     *
     * @param lengthInBytes the length of the nonce in bytes
     * @return the generated nonce as base64 encoded string
     * @throws SdkException if nonce generation fails
     */
    String generateNonce(int lengthInBytes) throws SdkException;

    /**
     * Generates a shared secret using ECDH.
     *
     * @param compressedPublicKey the compressed public key from the other party
     * @param privateKeyBytes the private key bytes
     * @param curveType the elliptic curve type
     * @return the shared secret
     * @throws SdkException if shared secret generation fails
     */
    byte[] generateSharedSecret(byte[] compressedPublicKey, byte[] privateKeyBytes, EccCurveType curveType) throws SdkException;
    
    /**
     * Merges client and server nonces.
     *
     * @param clientNonce the client nonce (base64 encoded)
     * @param serverNonce the server nonce (base64 encoded)
     * @return the merged nonce
     * @throws SdkException if merging fails
     */
    byte[] mergeNonce(String clientNonce, String serverNonce) throws SdkException;
    
    /**
     * Merges shared secret and nonce to create encryption key.
     *
     * @param sharedSecret the shared secret
     * @param mergedNonce the merged nonce
     * @param cipherType the cipher type
     * @return the encryption key
     * @throws SdkException if merging fails
     */
    byte[] mergeSharedSecretAndNonce(byte[] sharedSecret, byte[] mergedNonce, SymmetricCipherType cipherType) throws SdkException;
    
    /**
     * Decrypts encrypted data.
     *
     * @param encryptedData the encrypted data (base64 encoded)
     * @param key the decryption key
     * @param iv the initialization vector (base64 encoded)
     * @param cipherType the cipher type
     * @param padding the padding scheme
     * @return the decrypted data
     * @throws SdkException if decryption fails
     */
    byte[] decrypt(String encryptedData, byte[] key, String iv, SymmetricCipherType cipherType, String padding) throws SdkException;
}