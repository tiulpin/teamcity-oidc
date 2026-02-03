package jetbrains.buildServer.oidc

import com.intellij.openapi.diagnostic.Logger
import jetbrains.buildServer.BuildProblemData
import jetbrains.buildServer.serverSide.BuildStartContext
import jetbrains.buildServer.serverSide.BuildStartContextProcessor
import jetbrains.buildServer.serverSide.Parameter
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SimpleParameter
import jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class OidcBuildStartContextProcessor(
    private val tokenGenerator: OidcTokenGenerator
) : BuildStartContextProcessor, PasswordsProvider {

    private val log = Logger.getInstance(OidcBuildStartContextProcessor::class.java.name)
    private val buildTokens = ConcurrentHashMap<Long, TokenEntry>()

    private val entryTtlSeconds = OidcConstants.MAX_TOKEN_LIFETIME_SECONDS * 2

    private data class TokenInfo(val paramName: String, val envVarName: String, val token: String)
    private data class TokenEntry(val tokens: List<TokenInfo>, val createdAt: Instant)

    override fun updateParameters(context: BuildStartContext) {
        val build = context.build
        val buildType = build.buildType ?: return
        val oidcFeatures = buildType.getBuildFeaturesOfType(OidcConstants.FEATURE_TYPE)

        if (oidcFeatures.isEmpty()) return

        log.debug("OIDC: Processing ${oidcFeatures.size} OIDC feature(s) for build ${build.buildId}")

        val tokens = mutableListOf<TokenInfo>()

        for (feature in oidcFeatures) {
            val params = feature.parameters
            val audience = params[OidcConstants.PARAM_AUDIENCE] ?: continue
            val envVar = params[OidcConstants.PARAM_ENV_VAR] ?: OidcConstants.DEFAULT_ENV_VAR
            val buildParam = params[OidcConstants.PARAM_BUILD_PARAM] ?: OidcConstants.DEFAULT_BUILD_PARAM

            try {
                val token = tokenGenerator.generateToken(build, audience)
                context.addSharedParameter(buildParam, token)
                context.addSharedParameter("env.$envVar", token)
                tokens.add(TokenInfo(buildParam, envVar, token))
                log.info("OIDC: Injected token for build ${build.buildId} with audience '$audience'")
            } catch (e: Exception) {
                val errorMessage = "OIDC: Failed to generate token: ${e.message}"
                log.error(errorMessage, e)
                build.addBuildProblem(
                    BuildProblemData.createBuildProblem(
                        "oidc_token_generation_failed_${audience.hashCode()}",
                        OidcConstants.FEATURE_TYPE,
                        errorMessage
                    )
                )
            }
        }

        if (tokens.isNotEmpty()) {
            evictStaleEntries()
            buildTokens[build.buildId] = TokenEntry(tokens, Instant.now())
        }
    }

    override fun getPasswordParameters(build: SBuild): Collection<Parameter> {
        val entry = buildTokens.remove(build.buildId) ?: return emptyList()
        return entry.tokens.flatMap {
            listOf(
                SimpleParameter(it.paramName, it.token),
                SimpleParameter("env.${it.envVarName}", it.token)
            )
        }
    }

    private fun evictStaleEntries() {
        val cutoff = Instant.now().minusSeconds(entryTtlSeconds)
        val staleKeys = buildTokens.entries
            .filter { it.value.createdAt.isBefore(cutoff) }
            .map { it.key }

        if (staleKeys.isNotEmpty()) {
            staleKeys.forEach { buildTokens.remove(it) }
            log.debug("OIDC: Evicted ${staleKeys.size} stale token entries")
        }
    }
}
