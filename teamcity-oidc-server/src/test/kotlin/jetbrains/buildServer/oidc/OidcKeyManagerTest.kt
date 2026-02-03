package jetbrains.buildServer.oidc

import io.mockk.every
import io.mockk.mockk
import jetbrains.buildServer.serverSide.ServerPaths
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class OidcKeyManagerTest {

    @TempDir
    lateinit var tempDir: Path

    private lateinit var serverPaths: ServerPaths
    private lateinit var keyManager: OidcKeyManager

    @BeforeEach
    fun setUp() {
        serverPaths = mockk {
            every { dataDirectory } returns tempDir.toFile()
        }

        keyManager = OidcKeyManager(serverPaths)
    }

    @Test
    fun `init generates new key pair when none exists`() {
        keyManager.init()

        val keyDir = File(tempDir.toFile(), OidcConstants.KEY_DIRECTORY)
        val privateKeyFile = File(keyDir, OidcConstants.PRIVATE_KEY_FILE)
        val publicKeyFile = File(keyDir, OidcConstants.PUBLIC_KEY_FILE)

        assertThat(privateKeyFile).exists()
        assertThat(publicKeyFile).exists()
    }

    @Test
    fun `init saves private key in PEM format`() {
        keyManager.init()

        val privateKeyFile = File(tempDir.toFile(), "${OidcConstants.KEY_DIRECTORY}/${OidcConstants.PRIVATE_KEY_FILE}")
        val content = privateKeyFile.readText()

        assertThat(content).startsWith("-----BEGIN PRIVATE KEY-----")
        assertThat(content).endsWith("-----END PRIVATE KEY-----\n")
    }

    @Test
    fun `init saves public key in PEM format`() {
        keyManager.init()

        val publicKeyFile = File(tempDir.toFile(), "${OidcConstants.KEY_DIRECTORY}/${OidcConstants.PUBLIC_KEY_FILE}")
        val content = publicKeyFile.readText()

        assertThat(content).startsWith("-----BEGIN PUBLIC KEY-----")
        assertThat(content).endsWith("-----END PUBLIC KEY-----\n")
    }

    @Test
    fun `init loads existing key pair`() {
        keyManager.init()
        val originalKeyId = keyManager.getKeyId()

        val newKeyManager = OidcKeyManager(serverPaths)
        newKeyManager.init()

        assertThat(newKeyManager.getKeyId()).isEqualTo(originalKeyId)
    }

    @Test
    fun `getKeyId returns consistent key ID`() {
        keyManager.init()

        val keyId1 = keyManager.getKeyId()
        val keyId2 = keyManager.getKeyId()

        assertThat(keyId1).isEqualTo(keyId2)
        assertThat(keyId1).hasSize(16) // 8 bytes as hex = 16 chars
    }

    @Test
    fun `getRsaKey returns key with RS256 algorithm`() {
        keyManager.init()

        val rsaKey = keyManager.getRsaKey()

        assertThat(rsaKey.algorithm.name).isEqualTo("RS256")
        assertThat(rsaKey.keyID).isEqualTo(keyManager.getKeyId())
    }

    @Test
    fun `getPublicJwk returns key without private component`() {
        keyManager.init()

        val publicJwk = keyManager.getPublicJwk()

        assertThat(publicJwk.isPrivate).isFalse()
        assertThat(publicJwk.keyID).isEqualTo(keyManager.getKeyId())
    }

    @Test
    fun `generated key can sign and verify JWT`() {
        keyManager.init()

        val rsaKey = keyManager.getRsaKey()

        val signer = com.nimbusds.jose.crypto.RSASSASigner(rsaKey)
        val header = com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
            .keyID(keyManager.getKeyId())
            .build()
        val claims = com.nimbusds.jwt.JWTClaimsSet.Builder()
            .subject("test")
            .build()
        val signedJwt = com.nimbusds.jwt.SignedJWT(header, claims)
        signedJwt.sign(signer)

        val verifier = com.nimbusds.jose.crypto.RSASSAVerifier(keyManager.getPublicJwk())
        assertThat(signedJwt.verify(verifier)).isTrue()
    }

    @Test
    fun `key pair is reloaded correctly after restart`() {
        keyManager.init()
        val originalRsaKey = keyManager.getRsaKey()

        val signer = com.nimbusds.jose.crypto.RSASSASigner(originalRsaKey)
        val header = com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
            .keyID(keyManager.getKeyId())
            .build()
        val claims = com.nimbusds.jwt.JWTClaimsSet.Builder()
            .subject("test")
            .build()
        val signedJwt = com.nimbusds.jwt.SignedJWT(header, claims)
        signedJwt.sign(signer)

        val newKeyManager = OidcKeyManager(serverPaths)
        newKeyManager.init()

        val verifier = com.nimbusds.jose.crypto.RSASSAVerifier(newKeyManager.getPublicJwk())
        assertThat(signedJwt.verify(verifier)).isTrue()
    }

    @Test
    fun `key ID is derived from public key hash`() {
        keyManager.init()

        val keyId = keyManager.getKeyId()

        // Key ID should be hex string (16 chars for 8 bytes)
        assertThat(keyId).matches("[0-9a-f]{16}")
    }
}
