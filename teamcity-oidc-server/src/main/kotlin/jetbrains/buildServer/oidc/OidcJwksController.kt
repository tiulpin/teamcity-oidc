package jetbrains.buildServer.oidc

import com.nimbusds.jose.jwk.JWKSet
import jetbrains.buildServer.controllers.AuthorizationInterceptor
import jetbrains.buildServer.controllers.BaseController
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.springframework.web.servlet.ModelAndView
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class OidcJwksController(
    webControllerManager: WebControllerManager,
    authorizationInterceptor: AuthorizationInterceptor,
    private val keyManager: OidcKeyManager
) : BaseController() {

    init {
        webControllerManager.registerController(OidcConstants.JWKS_PATH, this)
        authorizationInterceptor.addPathNotRequiringAuth(OidcConstants.JWKS_PATH)
    }

    override fun doHandle(request: HttpServletRequest, response: HttpServletResponse): ModelAndView? {
        val publicJwk = keyManager.getPublicJwk()
        val jwkSet = JWKSet(publicJwk)

        response.contentType = "application/json"
        response.characterEncoding = "UTF-8"
        response.setHeader("Cache-Control", "public, max-age=300")
        response.writer.write(jwkSet.toString())

        return null
    }
}
