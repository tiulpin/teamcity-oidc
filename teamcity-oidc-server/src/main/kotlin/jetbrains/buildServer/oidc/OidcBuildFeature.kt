package jetbrains.buildServer.oidc

import jetbrains.buildServer.serverSide.BuildFeature
import jetbrains.buildServer.serverSide.InvalidProperty
import jetbrains.buildServer.serverSide.PropertiesProcessor
import jetbrains.buildServer.web.openapi.PluginDescriptor

class OidcBuildFeature(
    private val pluginDescriptor: PluginDescriptor
) : BuildFeature() {

    companion object {
        private val ENV_VAR_PATTERN = Regex("^[A-Za-z_][A-Za-z0-9_]*$")
        private val BUILD_PARAM_PATTERN = Regex("^[A-Za-z_][A-Za-z0-9_.]*$")
    }

    override fun getType(): String = OidcConstants.FEATURE_TYPE

    override fun getDisplayName(): String = OidcConstants.FEATURE_DISPLAY_NAME

    override fun getEditParametersUrl(): String? {
        return pluginDescriptor.getPluginResourcesPath("oidcBuildFeature.jsp")
    }

    override fun isMultipleFeaturesPerBuildTypeAllowed(): Boolean = true

    override fun describeParameters(params: MutableMap<String, String>): String {
        val audience = params[OidcConstants.PARAM_AUDIENCE] ?: "not set"
        val envVar = params[OidcConstants.PARAM_ENV_VAR] ?: OidcConstants.DEFAULT_ENV_VAR
        return "Audience: $audience, Env: $envVar"
    }

    override fun getParametersProcessor(): PropertiesProcessor {
        return PropertiesProcessor { properties ->
            val errors = mutableListOf<InvalidProperty>()

            val audience = properties[OidcConstants.PARAM_AUDIENCE]
            if (audience.isNullOrBlank()) {
                errors.add(InvalidProperty(OidcConstants.PARAM_AUDIENCE, "Audience is required"))
            }

            val envVar = properties[OidcConstants.PARAM_ENV_VAR]
            if (!envVar.isNullOrBlank() && !ENV_VAR_PATTERN.matches(envVar)) {
                errors.add(InvalidProperty(
                    OidcConstants.PARAM_ENV_VAR,
                    "Invalid environment variable name. Must start with a letter or underscore, contain only alphanumeric characters and underscores."
                ))
            }

            val buildParam = properties[OidcConstants.PARAM_BUILD_PARAM]
            if (!buildParam.isNullOrBlank() && !BUILD_PARAM_PATTERN.matches(buildParam)) {
                errors.add(InvalidProperty(
                    OidcConstants.PARAM_BUILD_PARAM,
                    "Invalid parameter name. Must start with a letter or underscore, contain only alphanumeric characters, underscores, and dots."
                ))
            }

            errors
        }
    }

    override fun getDefaultParameters(): MutableMap<String, String> {
        return mutableMapOf(
            OidcConstants.PARAM_ENV_VAR to OidcConstants.DEFAULT_ENV_VAR,
            OidcConstants.PARAM_BUILD_PARAM to OidcConstants.DEFAULT_BUILD_PARAM
        )
    }
}
