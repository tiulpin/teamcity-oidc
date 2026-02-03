package jetbrains.buildServer.oidc

import com.intellij.openapi.diagnostic.Logger
import com.nimbusds.jose.jwk.RSAKey
import jetbrains.buildServer.serverSide.ServerPaths
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.EnumSet

class OidcKeyManager(private val serverPaths: ServerPaths) {

    private val log = Logger.getInstance(OidcKeyManager::class.java.name)

    private lateinit var keyPair: KeyPair
    private lateinit var keyId: String
    private lateinit var rsaKey: RSAKey

    fun init() {
        val keyDir = File(serverPaths.dataDirectory, OidcConstants.KEY_DIRECTORY)
        val privateKeyFile = File(keyDir, OidcConstants.PRIVATE_KEY_FILE)
        val publicKeyFile = File(keyDir, OidcConstants.PUBLIC_KEY_FILE)

        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            log.info("OIDC: Loading existing key pair from ${keyDir.absolutePath}")
            keyPair = loadKeyPair(privateKeyFile, publicKeyFile)
        } else {
            log.info("OIDC: Generating new key pair in ${keyDir.absolutePath}")
            if (!keyDir.exists() && !keyDir.mkdirs()) {
                throw IllegalStateException("OIDC: Failed to create key directory: ${keyDir.absolutePath}")
            }
            keyPair = generateKeyPair()
            saveKeyPair(keyPair, privateKeyFile, publicKeyFile)
            setRestrictivePermissions(privateKeyFile)
        }

        keyId = computeKeyId(keyPair.public as RSAPublicKey)
        rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(keyId)
            .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
            .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
            .build()

        log.info("OIDC: Key manager initialized with key ID: $keyId")
    }

    fun getKeyId(): String = keyId
    fun getRsaKey(): RSAKey = rsaKey
    fun getPublicJwk(): RSAKey = rsaKey.toPublicJWK()

    private fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(OidcConstants.KEY_SIZE)
        return generator.generateKeyPair()
    }

    private fun saveKeyPair(keyPair: KeyPair, privateKeyFile: File, publicKeyFile: File) {
        privateKeyFile.writeText(toPem("PRIVATE KEY", keyPair.private.encoded))
        publicKeyFile.writeText(toPem("PUBLIC KEY", keyPair.public.encoded))
    }

    private fun setRestrictivePermissions(file: File) {
        try {
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                val ownerOnly = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
                Files.setPosixFilePermissions(file.toPath(), ownerOnly)
            } else {
                file.setReadable(false, false)
                file.setWritable(false, false)
                file.setExecutable(false, false)
                file.setReadable(true, true)
                file.setWritable(true, true)
            }
        } catch (e: Exception) {
            log.warn("OIDC: Could not set restrictive permissions on ${file.name}: ${e.message}")
        }
    }

    private fun loadKeyPair(privateKeyFile: File, publicKeyFile: File): KeyPair {
        val privateKeyBytes = fromPem(privateKeyFile.readText())
        val publicKeyBytes = fromPem(publicKeyFile.readText())

        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

        return KeyPair(publicKey, privateKey)
    }

    private fun toPem(type: String, data: ByteArray): String {
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(data)
        return "-----BEGIN $type-----\n$encoded\n-----END $type-----\n"
    }

    private fun fromPem(pem: String): ByteArray {
        val base64 = pem.lines().filter { !it.startsWith("-----") }.joinToString("")
        return Base64.getDecoder().decode(base64)
    }

    private fun computeKeyId(publicKey: RSAPublicKey): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
        return hash.take(8).joinToString("") { "%02x".format(it) }
    }
}
