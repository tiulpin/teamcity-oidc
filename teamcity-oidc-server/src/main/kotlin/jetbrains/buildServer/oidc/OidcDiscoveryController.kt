package jetbrains.buildServer.oidc

import com.google.gson.Gson
import jetbrains.buildServer.controllers.AuthorizationInterceptor
import jetbrains.buildServer.controllers.BaseController
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.springframework.web.servlet.ModelAndView
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class OidcDiscoveryController(
    webControllerManager: WebControllerManager,
    authorizationInterceptor: AuthorizationInterceptor,
    private val tokenGenerator: OidcTokenGenerator
) : BaseController() {

    private val gson = Gson()

    init {
        webControllerManager.registerController(OidcConstants.DISCOVERY_PATH, this)
        authorizationInterceptor.addPathNotRequiringAuth(OidcConstants.DISCOVERY_PATH)
    }

    override fun doHandle(request: HttpServletRequest, response: HttpServletResponse): ModelAndView? {
        val issuer = tokenGenerator.getIssuer()

        val discoveryDocument = mapOf(
            "issuer" to issuer,
            "jwks_uri" to "$issuer${OidcConstants.JWKS_RELATIVE_PATH}",
            "subject_types_supported" to listOf("public"),
            "response_types_supported" to listOf("id_token"),
            "id_token_signing_alg_values_supported" to listOf(OidcConstants.KEY_ALGORITHM),
            "claims_supported" to listOf(
                "iss", "sub", "aud", "exp", "iat", "nbf", "jti",
                "project_id", "project_name", "build_type_id", "build_type_name",
                "build_id", "build_number", "ref", "ref_type", "default_branch",
                "server_url", "triggered_by", "agent_name"
            )
        )

        response.contentType = "application/json"
        response.characterEncoding = "UTF-8"
        response.setHeader("Cache-Control", "public, max-age=3600")
        response.writer.write(gson.toJson(discoveryDocument))

        return null
    }
}
