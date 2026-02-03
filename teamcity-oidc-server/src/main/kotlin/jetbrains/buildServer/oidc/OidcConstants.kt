package jetbrains.buildServer.oidc

object OidcConstants {
    const val FEATURE_TYPE = "teamcity-oidc-token"
    const val FEATURE_DISPLAY_NAME = "OIDC Token"

    const val PARAM_AUDIENCE = "oidc.audience"
    const val PARAM_ENV_VAR = "oidc.env.var"
    const val PARAM_BUILD_PARAM = "oidc.parameter"

    const val DEFAULT_ENV_VAR = "TEAMCITY_OIDC_TOKEN"
    const val DEFAULT_BUILD_PARAM = "teamcity.oidc.token"

    const val OIDC_BASE_PATH = "/app/oidc"
    const val DISCOVERY_PATH = "$OIDC_BASE_PATH/.well-known/openid-configuration"
    const val JWKS_PATH = "$OIDC_BASE_PATH/.well-known/jwks.json"
    const val JWKS_RELATIVE_PATH = "/.well-known/jwks.json"

    const val KEY_ALGORITHM = "RS256"
    const val KEY_SIZE = 3072
    const val KEY_DIRECTORY = "config/oidc-keys"
    const val PRIVATE_KEY_FILE = "private.pem"
    const val PUBLIC_KEY_FILE = "public.pem"

    const val DEFAULT_TOKEN_LIFETIME_SECONDS = 3600L
    const val MAX_TOKEN_LIFETIME_SECONDS = 7200L
}
