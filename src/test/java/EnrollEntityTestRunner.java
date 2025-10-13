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

import org.omnione.did.data.model.did.DidDocument;
import org.omnione.did.data.model.enums.vc.RoleType;
import org.omnione.did.oid4vc.enrollment.core.crypto.DefaultCryptoProvider;
import org.omnione.did.oid4vc.enrollment.core.enroll.EnrollEntityBuilder;
import org.omnione.did.oid4vc.enrollment.core.enroll.EnrollEntityConfig;
import org.omnione.did.oid4vc.enrollment.core.enroll.EnrollEntitySDK;
import org.omnione.did.oid4vc.enrollment.core.entity.DefaultEntityProvider;
import org.omnione.did.oid4vc.enrollment.core.model.EnrollResponse;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.omnione.did.wallet.key.WalletManagerFactory;
import org.omnione.did.wallet.key.WalletManagerFactory.WalletManagerType;
import org.omnione.did.wallet.key.WalletManagerInterface;

/**
 * Test runner for EnrollEntitySDK.
 * This demonstrates how to create and use the SDK.
 */
public class EnrollEntityTestRunner {

    /**
     * Gets the absolute path to a resource file.
     *
     * @param resourceName the resource file name
     * @return the absolute path to the resource file
     */
    private static String getResourceFilePath(String resourceName) {
        // Get current working directory (project root)
        String currentDir = System.getProperty("user.dir");
        Path resourcePath = Paths.get(currentDir, "src", "main", "resources", resourceName);
        return resourcePath.toAbsolutePath().toString();
    }

    /**
     * Loads the content of a resource file as a String.
     *
     * @param resourcePath the path to the resource file
     * @return the file content as a String
     * @throws IOException if the file cannot be read
     */
    private static String loadResourceAsString(String resourcePath) throws IOException {
        try (InputStream inputStream = EnrollEntityTestRunner.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    public static void main(String[] args) {
        System.out.println("=== EnrollEntity SDK Test Runner ===");
        
        try {
            // 1. Create configuration
            EnrollEntityConfig config = EnrollEntityConfig.builder()
                    .tasBaseUrl("http://192.168.3.130:18090")  // Replace with actual TAS URL
                    .build();

            // Load File Wallet from resources (using absolute path)
            WalletManagerInterface walletManager = WalletManagerFactory.getWalletManager(WalletManagerType.FILE);
            String walletFilePath = getResourceFilePath("oid_issuer.wallet");
            System.out.println("Wallet file path: " + walletFilePath);
            walletManager.connect(walletFilePath, "123456".toCharArray());

            // Load DID document from resources
            String didDocJsonStr = loadResourceAsString("oid_issuer.did");
            DidDocument didDoc = new DidDocument(didDocJsonStr);

            // 2. Create SDK instance with default providers
            EnrollEntitySDK sdk = EnrollEntityBuilder.newBuilder()
                    .withConfig(config)
                    .withCrypto(new DefaultCryptoProvider())
                    .withEntity(new DefaultEntityProvider(walletManager, didDoc))
                    .build();

            // 3. RegisterDidToTaRequest
            sdk.registerDidToTas(
                  didDoc,
                  "oid4vc_issuer",
                  "https://entity.example.com",
                  "https://entity.example.com",
                  RoleType.ISSUER // ISSUER, VERIFIER, OP_PROVIDER, and others
            );

            // 일단 위에 꺼 호출하고 TAS Admin에 접속해서 승인(Approval)하고 밑에 꺼 호출해야 함

            // 4. Execute enrollment
            System.out.println("\n=== Starting Enrollment ===");
            EnrollResponse response = sdk.enrollEntity();

            // 5. Check results
            if (response.isSuccess()) {
                System.out.println("Enrollment SUCCESS!");
                System.out.println("Transaction ID: " + response.getTransactionId());
                System.out.println("Certificate VC ID: " + response.getCertificateVcId());
                System.out.println("Processing Time: " + response.getProcessingTimeMs() + "ms");
            } else {
                System.out.println("Enrollment FAILED!");
                System.out.println("Error Code: " + response.getErrorCode());
                System.out.println("Error Message: " + response.getErrorMessage());
            }
        } catch (Exception e) {
            System.err.println("Test failed with exception:");
            e.printStackTrace();
        }
        
        System.out.println("\n=== Test Complete ===");
    }
}