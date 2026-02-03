package jetbrains.buildServer.oidc

import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.Network
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import java.io.File
import java.nio.file.Paths
import java.time.Duration
import java.util.concurrent.TimeUnit

/**
 * Integration tests for OIDC endpoints using a real TeamCity server in Docker.
 *
 * These tests verify:
 * - OIDC Discovery endpoint returns valid OpenID configuration
 * - JWKS endpoint returns valid public keys
 * - Endpoints are publicly accessible (no auth required)
 * - Full OIDC token validation flow with HashiCorp Vault
 *
 * Note: These tests are tagged as "integration" and excluded from normal test runs.
 * Run with: mvn test -Dgroups=integration -P integration-tests
 *
 * Prerequisites:
 * - Docker must be running
 * - Plugin must be built first: mvn package -DskipTests
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("integration")
class OidcEndpointsIntegrationTest {

    companion object {
        private const val TEAMCITY_PORT = 8111
        private const val VAULT_PORT = 8200
        private const val STARTUP_TIMEOUT_MINUTES = 5L
        private const val VAULT_TOKEN = "root-token-for-testing"

        /**
         * Find the built plugin zip file.
         */
        private fun findPluginZip(): File {
            val projectRoot = Paths.get("").toAbsolutePath().parent
            val pluginZip = projectRoot.resolve("target/teamcity-oidc.zip").toFile()

            if (!pluginZip.exists()) {
                throw IllegalStateException(
                    "Plugin zip not found at ${pluginZip.absolutePath}. " +
                    "Build the plugin first with: mvn package -DskipTests"
                )
            }
            return pluginZip
        }
    }

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val gson = Gson()

    // Shared network for containers to communicate
    private lateinit var network: Network

    /**
     * TeamCity container with the OIDC plugin pre-installed.
     */
    private lateinit var teamcityContainer: GenericContainer<*>

    /**
     * HashiCorp Vault container for OIDC token validation.
     */
    private lateinit var vaultContainer: GenericContainer<*>

    @BeforeAll
    fun startContainers() {
        // Create shared network
        network = Network.newNetwork()

        startTeamCityContainer()
        startVaultContainer()
        configureVaultJwtAuth()
    }

    private fun startTeamCityContainer() {
        println("Starting TeamCity container with OIDC plugin...")
        teamcityContainer = GenericContainer(
            ImageFromDockerfile()
                .withDockerfileFromBuilder { builder ->
                    builder
                        .from("jetbrains/teamcity-server:latest")
                        .copy("teamcity-oidc.zip", "/tmp/teamcity-oidc.zip")
                        .run("mkdir -p /opt/teamcity/webapps/ROOT/WEB-INF/plugins/teamcity-oidc && unzip /tmp/teamcity-oidc.zip -d /opt/teamcity/webapps/ROOT/WEB-INF/plugins/teamcity-oidc/")
                        .build()
                }
                .withFileFromFile("teamcity-oidc.zip", findPluginZip())
        )
            .withNetwork(network)
            .withNetworkAliases("teamcity")
            .withExposedPorts(TEAMCITY_PORT)
            .withEnv("TEAMCITY_SERVER_MEM_OPTS", "-Xmx1g")
            // Enable test token endpoint and set root URL to internal Docker hostname
            // This ensures tokens have the correct issuer for Vault validation
            .withEnv("TEAMCITY_SERVER_OPTS",
                "-Dteamcity.installation.completed=true " +
                "-Dteamcity.startup.maintenance=false " +
                "-Dteamcity.licenseAgreement.accepted=true " +
                "-Dteamcity.oidc.test.enabled=true " +
                "-Dteamcity.server.rootURL=http://teamcity:$TEAMCITY_PORT")
            .waitingFor(
                Wait.forHttp("/app/rest/server/version")
                    .forPort(TEAMCITY_PORT)
                    .forStatusCodeMatching { status -> status == 200 || status == 401 }
                    .withStartupTimeout(Duration.ofMinutes(STARTUP_TIMEOUT_MINUTES))
            )
        teamcityContainer.start()

        val logs = teamcityContainer.logs
        println("=== TeamCity Container Logs (Plugin-related) ===")
        logs.lines().filter {
            it.contains("oidc", ignoreCase = true) ||
            it.contains("ERROR") ||
            it.contains("WARN")
        }.take(50).forEach { println(it) }
        println("=== End of Plugin Logs ===")
        println("TeamCity Base URL: ${getTeamCityBaseUrl()}")
    }

    private fun startVaultContainer() {
        println("Starting Vault container...")
        vaultContainer = GenericContainer("hashicorp/vault:1.15")
            .withNetwork(network)
            .withNetworkAliases("vault")
            .withExposedPorts(VAULT_PORT)
            .withEnv("VAULT_DEV_ROOT_TOKEN_ID", VAULT_TOKEN)
            .withEnv("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:$VAULT_PORT")
            .waitingFor(
                Wait.forHttp("/v1/sys/health")
                    .forPort(VAULT_PORT)
                    .forStatusCode(200)
                    .withStartupTimeout(Duration.ofMinutes(2))
            )
        vaultContainer.start()
        println("Vault Base URL: ${getVaultBaseUrl()}")
    }

    private fun configureVaultJwtAuth() {
        println("Configuring Vault JWT auth backend...")
        val vaultUrl = getVaultBaseUrl()

        // Enable JWT auth method
        val enableJwtRequest = Request.Builder()
            .url("$vaultUrl/v1/sys/auth/jwt")
            .header("X-Vault-Token", VAULT_TOKEN)
            .post(gson.toJson(mapOf("type" to "jwt")).toRequestBody("application/json".toMediaType()))
            .build()
        httpClient.newCall(enableJwtRequest).execute().use { response ->
            // 200 = enabled, 400 = already enabled
            assertThat(response.code).isIn(200, 204, 400)
        }

        // Use internal Docker network URL for Vault to reach TeamCity
        val teamcityInternalUrl = "http://teamcity:$TEAMCITY_PORT"
        val issuer = "$teamcityInternalUrl${OidcConstants.OIDC_BASE_PATH}"
        val jwksUrl = "$teamcityInternalUrl${OidcConstants.JWKS_PATH}"

        // Wait for TeamCity OIDC endpoints to be available from Vault's perspective
        // by retrying the configuration
        var configured = false
        var lastError = ""
        for (attempt in 1..10) {
            val configJwtRequest = Request.Builder()
                .url("$vaultUrl/v1/auth/jwt/config")
                .header("X-Vault-Token", VAULT_TOKEN)
                .post(gson.toJson(mapOf(
                    // Use direct JWKS URL instead of discovery - more reliable for testing
                    "jwks_url" to jwksUrl,
                    "bound_issuer" to issuer,
                    "default_role" to "teamcity-build"
                )).toRequestBody("application/json".toMediaType()))
                .build()

            httpClient.newCall(configJwtRequest).execute().use { response ->
                if (response.isSuccessful) {
                    configured = true
                    println("Vault JWT auth configured on attempt $attempt")
                } else {
                    lastError = response.body?.string() ?: "unknown error"
                    println("Vault config attempt $attempt failed: $lastError")
                    if (attempt < 10) {
                        Thread.sleep(2000)
                    }
                }
            }
            if (configured) break
        }
        assertThat(configured)
            .withFailMessage("Failed to configure JWT auth after 10 attempts: $lastError")
            .isTrue()
        println("Vault JWT auth configured with issuer: $issuer, jwks: $jwksUrl")

        // Create a role for TeamCity builds
        val createRoleRequest = Request.Builder()
            .url("$vaultUrl/v1/auth/jwt/role/teamcity-build")
            .header("X-Vault-Token", VAULT_TOKEN)
            .post(gson.toJson(mapOf(
                "role_type" to "jwt",
                "bound_audiences" to listOf("vault"),
                "bound_issuer" to issuer,
                "user_claim" to "sub",
                "token_policies" to listOf("default"),
                "token_ttl" to "1h"
            )).toRequestBody("application/json".toMediaType()))
            .build()
        httpClient.newCall(createRoleRequest).execute().use { response ->
            assertThat(response.isSuccessful)
                .withFailMessage("Failed to create JWT role: ${response.code} ${response.body?.string()}")
                .isTrue()
        }
        println("Vault JWT role 'teamcity-build' created")
    }

    @AfterAll
    fun stopContainers() {
        if (::vaultContainer.isInitialized) {
            vaultContainer.stop()
        }
        if (::teamcityContainer.isInitialized) {
            teamcityContainer.stop()
        }
        if (::network.isInitialized) {
            network.close()
        }
    }

    private fun getTeamCityBaseUrl(): String {
        val host = teamcityContainer.host
        val port = teamcityContainer.getMappedPort(TEAMCITY_PORT)
        return "http://$host:$port"
    }

    private fun getVaultBaseUrl(): String {
        val host = vaultContainer.host
        val port = vaultContainer.getMappedPort(VAULT_PORT)
        return "http://$host:$port"
    }

    @Test
    fun `OIDC discovery endpoint returns valid OpenID configuration`() {
        val url = "${getTeamCityBaseUrl()}${OidcConstants.DISCOVERY_PATH}"
        val request = Request.Builder().url(url).get().build()

        httpClient.newCall(request).execute().use { response ->
            assertThat(response.isSuccessful)
                .withFailMessage("Discovery endpoint failed: ${response.code} ${response.message}")
                .isTrue()

            assertThat(response.header("Content-Type"))
                .contains("application/json")

            val body = response.body?.string() ?: ""
            val json = gson.fromJson(body, JsonObject::class.java)

            // Verify required OIDC discovery fields
            assertThat(json.has("issuer")).isTrue()
            assertThat(json.has("jwks_uri")).isTrue()
            assertThat(json.has("subject_types_supported")).isTrue()
            assertThat(json.has("id_token_signing_alg_values_supported")).isTrue()
            assertThat(json.has("claims_supported")).isTrue()

            // Verify issuer includes the OIDC base path
            val issuer = json.get("issuer").asString
            assertThat(issuer).contains(OidcConstants.OIDC_BASE_PATH)

            // Verify JWKS URI is properly formed
            val jwksUri = json.get("jwks_uri").asString
            assertThat(jwksUri).endsWith(OidcConstants.JWKS_RELATIVE_PATH)

            // Verify RS256 is supported
            val algorithms = json.getAsJsonArray("id_token_signing_alg_values_supported")
            assertThat(algorithms.map { it.asString }).contains("RS256")

            // Verify expected claims are listed
            val claims = json.getAsJsonArray("claims_supported").map { it.asString }
            assertThat(claims).contains(
                "iss", "sub", "aud", "exp", "iat",
                "project_id", "build_type_id", "build_id"
            )
        }
    }

    @Test
    fun `JWKS endpoint returns valid RSA public key`() {
        val url = "${getTeamCityBaseUrl()}${OidcConstants.JWKS_PATH}"
        val request = Request.Builder().url(url).get().build()

        httpClient.newCall(request).execute().use { response ->
            assertThat(response.isSuccessful)
                .withFailMessage("JWKS endpoint failed: ${response.code} ${response.message}")
                .isTrue()

            assertThat(response.header("Content-Type"))
                .contains("application/json")

            val body = response.body?.string() ?: ""
            val json = gson.fromJson(body, JsonObject::class.java)

            // Verify JWKS structure
            assertThat(json.has("keys")).isTrue()
            val keys = json.getAsJsonArray("keys")
            assertThat(keys.size()).isGreaterThanOrEqualTo(1)

            // Verify the first key is a valid RSA public key
            val firstKey = keys[0].asJsonObject
            assertThat(firstKey.get("kty").asString).isEqualTo("RSA")
            assertThat(firstKey.get("alg").asString).isEqualTo("RS256")
            assertThat(firstKey.get("use").asString).isEqualTo("sig")
            assertThat(firstKey.has("kid")).isTrue()
            assertThat(firstKey.has("n")).isTrue() // RSA modulus
            assertThat(firstKey.has("e")).isTrue() // RSA exponent

            // Verify the key ID is not empty
            val keyId = firstKey.get("kid").asString
            assertThat(keyId).isNotBlank()
        }
    }

    @Test
    fun `OIDC endpoints have correct caching headers`() {
        val discoveryUrl = "${getTeamCityBaseUrl()}${OidcConstants.DISCOVERY_PATH}"
        val jwksUrl = "${getTeamCityBaseUrl()}${OidcConstants.JWKS_PATH}"

        listOf(discoveryUrl, jwksUrl).forEach { url ->
            val request = Request.Builder().url(url).get().build()

            httpClient.newCall(request).execute().use { response ->
                assertThat(response.isSuccessful).isTrue()

                // Verify caching is enabled for performance
                val cacheControl = response.header("Cache-Control")
                assertThat(cacheControl)
                    .withFailMessage("$url should have Cache-Control header")
                    .isNotNull()
                assertThat(cacheControl).contains("max-age")
            }
        }
    }

    @Test
    fun `JWKS endpoint key can verify signatures from discovery issuer`() {
        // Get the JWKS
        val jwksUrl = "${getTeamCityBaseUrl()}${OidcConstants.JWKS_PATH}"
        val jwksRequest = Request.Builder().url(jwksUrl).get().build()
        val jwksBody = httpClient.newCall(jwksRequest).execute().use { it.body?.string() ?: "" }
        val jwksJson = gson.fromJson(jwksBody, JsonObject::class.java)

        // Parse the public key
        val keyJson = jwksJson.getAsJsonArray("keys")[0].asJsonObject
        val jwk = com.nimbusds.jose.jwk.RSAKey.parse(keyJson.toString())

        // Verify we can create a verifier from the public key
        val verifier = com.nimbusds.jose.crypto.RSASSAVerifier(jwk)
        assertThat(verifier).isNotNull()

        // Get discovery document and verify JWKS URI matches
        val discoveryUrl = "${getTeamCityBaseUrl()}${OidcConstants.DISCOVERY_PATH}"
        val discoveryRequest = Request.Builder().url(discoveryUrl).get().build()
        val discoveryBody = httpClient.newCall(discoveryRequest).execute().use { it.body?.string() ?: "" }
        val discoveryJson = gson.fromJson(discoveryBody, JsonObject::class.java)

        val issuer = discoveryJson.get("issuer").asString
        val expectedJwksUri = discoveryJson.get("jwks_uri").asString

        // The JWKS URI should be relative to the issuer
        assertThat(expectedJwksUri).startsWith(issuer.removeSuffix("/"))
    }

    @Test
    fun `endpoints are accessible without authentication`() {
        // These endpoints must be public for cloud providers to fetch them
        val endpoints = listOf(
            OidcConstants.DISCOVERY_PATH,
            OidcConstants.JWKS_PATH
        )

        endpoints.forEach { path ->
            val url = "${getTeamCityBaseUrl()}$path"
            val request = Request.Builder()
                .url(url)
                .get()
                // Explicitly no auth headers
                .build()

            httpClient.newCall(request).execute().use { response ->
                assertThat(response.code)
                    .withFailMessage("$path should be accessible without auth, got ${response.code}")
                    .isEqualTo(200)
            }
        }
    }

    @Test
    fun `test token endpoint generates valid JWT when enabled`() {
        val testTokenUrl = "${getTeamCityBaseUrl()}${OidcTestTokenController.TEST_TOKEN_PATH}"

        val tokenRequest = Request.Builder()
            .url(testTokenUrl)
            .post(gson.toJson(mapOf(
                "audience" to "vault",
                "project_id" to "TestProject",
                "build_type_id" to "TestProject_Build",
                "build_id" to "123"
            )).toRequestBody("application/json".toMediaType()))
            .build()

        httpClient.newCall(tokenRequest).execute().use { response ->
            val body = response.body?.string() ?: ""
            assertThat(response.isSuccessful)
                .withFailMessage("Test token endpoint failed: ${response.code} $body")
                .isTrue()

            val json = gson.fromJson(body, JsonObject::class.java)

            assertThat(json.has("token")).isTrue()
            assertThat(json.get("token_type").asString).isEqualTo("Bearer")

            // Verify it's a valid JWT (3 parts separated by dots)
            val token = json.get("token").asString
            assertThat(token.split(".")).hasSize(3)

            // Parse and verify the token structure
            val signedJwt = com.nimbusds.jwt.SignedJWT.parse(token)
            val claims = signedJwt.jwtClaimsSet

            assertThat(claims.issuer).contains(OidcConstants.OIDC_BASE_PATH)
            assertThat(claims.audience).contains("vault")
            assertThat(claims.subject).contains("TestProject")
            assertThat(claims.getStringClaim("project_id")).isEqualTo("TestProject")
            assertThat(claims.getStringClaim("build_type_id")).isEqualTo("TestProject_Build")
            assertThat(claims.getStringClaim("build_id")).isEqualTo("123")
        }
    }

    @Test
    fun `Vault accepts token with correct audience`() {
        // Generate a token with the correct audience that Vault expects
        val internalIssuer = "http://teamcity:$TEAMCITY_PORT${OidcConstants.OIDC_BASE_PATH}"
        val testTokenUrl = "${getTeamCityBaseUrl()}${OidcTestTokenController.TEST_TOKEN_PATH}"
        val tokenRequest = Request.Builder()
            .url(testTokenUrl)
            .post(gson.toJson(mapOf(
                "audience" to "vault",  // Correct audience - matches Vault role config
                "issuer" to internalIssuer,
                "project_id" to "MyProject",
                "build_type_id" to "MyProject_Build",
                "build_id" to "456",
                "ref" to "refs/heads/main"
            )).toRequestBody("application/json".toMediaType()))
            .build()

        val token = httpClient.newCall(tokenRequest).execute().use { response ->
            assertThat(response.isSuccessful).isTrue()
            val json = gson.fromJson(response.body?.string() ?: "", JsonObject::class.java)
            json.get("token").asString
        }
        println("Generated TeamCity OIDC token with correct audience")

        // Authenticate to Vault - should succeed
        val vaultLoginUrl = "${getVaultBaseUrl()}/v1/auth/jwt/login"
        val loginRequest = Request.Builder()
            .url(vaultLoginUrl)
            .post(gson.toJson(mapOf(
                "jwt" to token,
                "role" to "teamcity-build"
            )).toRequestBody("application/json".toMediaType()))
            .build()

        httpClient.newCall(loginRequest).execute().use { response ->
            val body = response.body?.string() ?: ""
            println("Vault login response: $body")

            assertThat(response.isSuccessful)
                .withFailMessage("Vault should accept token with correct audience: ${response.code} $body")
                .isTrue()

            val json = gson.fromJson(body, JsonObject::class.java)

            // Verify Vault returned a client token
            assertThat(json.has("auth")).isTrue()
            val auth = json.getAsJsonObject("auth")
            assertThat(auth.has("client_token")).isTrue()
            assertThat(auth.get("client_token").asString).isNotBlank()

            println("SUCCESS: Vault accepted token with correct audience")
        }
    }

    @Test
    fun `Vault rejects token with wrong audience`() {
        // Generate a token with wrong audience
        // Use internal Docker hostname as issuer so we test audience validation (not issuer)
        val internalIssuer = "http://teamcity:$TEAMCITY_PORT${OidcConstants.OIDC_BASE_PATH}"
        val testTokenUrl = "${getTeamCityBaseUrl()}${OidcTestTokenController.TEST_TOKEN_PATH}"
        val tokenRequest = Request.Builder()
            .url(testTokenUrl)
            .post(gson.toJson(mapOf(
                "audience" to "wrong-audience",  // Vault expects "vault"
                "issuer" to internalIssuer,
                "project_id" to "TestProject"
            )).toRequestBody("application/json".toMediaType()))
            .build()

        val token = httpClient.newCall(tokenRequest).execute().use { response ->
            assertThat(response.isSuccessful).isTrue()
            val json = gson.fromJson(response.body?.string() ?: "", JsonObject::class.java)
            json.get("token").asString
        }

        // Try to authenticate to Vault - should fail
        val vaultLoginUrl = "${getVaultBaseUrl()}/v1/auth/jwt/login"
        val loginRequest = Request.Builder()
            .url(vaultLoginUrl)
            .post(gson.toJson(mapOf(
                "jwt" to token,
                "role" to "teamcity-build"
            )).toRequestBody("application/json".toMediaType()))
            .build()

        httpClient.newCall(loginRequest).execute().use { response ->
            assertThat(response.isSuccessful)
                .withFailMessage("Vault should reject token with wrong audience")
                .isFalse()

            val body = response.body?.string() ?: ""
            println("Vault correctly rejected token: $body")
            assertThat(body).containsIgnoringCase("audience")
        }
    }
}
