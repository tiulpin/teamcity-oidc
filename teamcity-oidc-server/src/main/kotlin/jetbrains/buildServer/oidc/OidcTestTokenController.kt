package jetbrains.buildServer.oidc

import com.google.gson.Gson
import com.intellij.openapi.diagnostic.Logger
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import jetbrains.buildServer.controllers.AuthorizationInterceptor
import jetbrains.buildServer.controllers.BaseController
import jetbrains.buildServer.serverSide.TeamCityProperties
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.springframework.web.servlet.ModelAndView
import java.time.Instant
import java.util.Date
import java.util.UUID
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Test endpoint for generating OIDC tokens without a real build.
 * Disabled by default. Enable with: -Dteamcity.oidc.test.enabled=true
 */
class OidcTestTokenController(
    webControllerManager: WebControllerManager,
    authorizationInterceptor: AuthorizationInterceptor,
    private val keyManager: OidcKeyManager,
    private val tokenGenerator: OidcTokenGenerator
) : BaseController() {

    private val log = Logger.getInstance(OidcTestTokenController::class.java.name)
    private val gson = Gson()

    companion object {
        const val TEST_TOKEN_PATH = "${OidcConstants.OIDC_BASE_PATH}/test/token"
        const val ENABLED_PROPERTY = "teamcity.oidc.test.enabled"
    }

    init {
        webControllerManager.registerController(TEST_TOKEN_PATH, this)
        authorizationInterceptor.addPathNotRequiringAuth(TEST_TOKEN_PATH)
        log.info("OIDC: Test token endpoint registered at $TEST_TOKEN_PATH (disabled by default)")
    }

    override fun doHandle(request: HttpServletRequest, response: HttpServletResponse): ModelAndView? {
        if (!isEnabled()) {
            response.status = HttpServletResponse.SC_NOT_FOUND
            response.contentType = "application/json"
            response.writer.write(gson.toJson(mapOf(
                "error" to "not_found",
                "error_description" to "Test endpoint disabled. Enable with -D$ENABLED_PROPERTY=true"
            )))
            return null
        }

        if (request.method != "POST") {
            response.status = HttpServletResponse.SC_METHOD_NOT_ALLOWED
            response.contentType = "application/json"
            response.writer.write(gson.toJson(mapOf("error" to "method_not_allowed")))
            return null
        }

        try {
            val body = request.reader.readText()
            @Suppress("UNCHECKED_CAST")
            val params = if (body.isNotBlank()) gson.fromJson(body, Map::class.java) as Map<String, Any> else emptyMap()

            response.contentType = "application/json"
            response.writer.write(gson.toJson(mapOf(
                "token" to generateTestToken(params),
                "token_type" to "Bearer"
            )))
        } catch (e: Exception) {
            log.warn("OIDC: Failed to generate test token", e)
            response.status = HttpServletResponse.SC_BAD_REQUEST
            response.contentType = "application/json"
            response.writer.write(gson.toJson(mapOf(
                "error" to "invalid_request",
                "error_description" to (e.message ?: "Failed to generate token")
            )))
        }

        return null
    }

    private fun isEnabled(): Boolean {
        return TeamCityProperties.getBoolean(ENABLED_PROPERTY)
    }

    private fun generateTestToken(params: Map<String, Any>): String {
        val now = Instant.now()
        val requestedLifetime = params["lifetime_seconds"]?.toString()?.toLongOrNull()
            ?: OidcConstants.DEFAULT_TOKEN_LIFETIME_SECONDS
        val expiry = now.plusSeconds(minOf(requestedLifetime, OidcConstants.MAX_TOKEN_LIFETIME_SECONDS))

        val issuer = tokenGenerator.getIssuer()
        val audience = params["audience"]?.toString() ?: "https://test.example.com"
        val projectId = params["project_id"]?.toString() ?: "TestProject"
        val buildTypeId = params["build_type_id"]?.toString() ?: "TestProject_Build"
        val ref = params["ref"]?.toString() ?: "refs/heads/main"

        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("project:$projectId:build_type:$buildTypeId:ref:$ref")
            .audience(audience)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiry))
            .notBeforeTime(Date.from(now))
            .jwtID(UUID.randomUUID().toString())
            .claim("project_id", projectId)
            .claim("project_name", params["project_name"]?.toString() ?: projectId)
            .claim("build_type_id", buildTypeId)
            .claim("build_type_name", params["build_type_name"]?.toString() ?: buildTypeId)
            .claim("build_id", params["build_id"]?.toString() ?: "1")
            .claim("build_number", params["build_number"]?.toString() ?: "1")
            .claim("ref", ref)
            .claim("ref_type", params["ref_type"]?.toString() ?: "branch")
            .claim("default_branch", params["default_branch"]?.toString()?.toBoolean() ?: true)
            .claim("server_url", issuer)
            .claim("agent_name", params["agent_name"]?.toString() ?: "test-agent")
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyManager.getKeyId()).build()
        return SignedJWT(header, claims).apply { sign(RSASSASigner(keyManager.getRsaKey())) }.serialize()
    }
}
