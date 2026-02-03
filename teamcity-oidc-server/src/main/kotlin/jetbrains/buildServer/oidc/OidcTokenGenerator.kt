package jetbrains.buildServer.oidc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import jetbrains.buildServer.serverSide.BuildTypeOptions
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SRunningBuild
import jetbrains.buildServer.serverSide.WebLinks
import java.time.Instant
import java.util.Date
import java.util.UUID

class OidcTokenGenerator(
    private val keyManager: OidcKeyManager,
    private val webLinks: WebLinks
) {
    private val signer: JWSSigner by lazy { RSASSASigner(keyManager.getRsaKey()) }

    fun generateToken(build: SRunningBuild, audience: String): String {
        val now = Instant.now()
        val expiry = calculateExpiry(build, now)
        val issuer = getIssuer()

        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(buildSubject(build))
            .audience(audience)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiry))
            .notBeforeTime(Date.from(now))
            .jwtID(UUID.randomUUID().toString())
            .claim("project_id", build.projectId)
            .claim("project_name", build.buildType?.project?.name ?: build.projectId)
            .claim("build_type_id", build.buildTypeId)
            .claim("build_type_name", build.buildType?.name ?: build.buildTypeId)
            .claim("build_id", build.buildId.toString())
            .claim("build_number", build.buildNumber)
            .claim("ref", getRef(build))
            .claim("ref_type", getRefType(build))
            .claim("default_branch", build.branch?.isDefaultBranch ?: true)
            .claim("server_url", issuer)
            .claim("agent_name", build.agent.name)
            .apply {
                build.triggeredBy.user?.let { claim("triggered_by", it.username) }
            }
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(keyManager.getKeyId())
            .build()

        return SignedJWT(header, claims).apply { sign(signer) }.serialize()
    }

    fun getIssuer(): String = "${webLinks.rootUrl.trimEnd('/')}${OidcConstants.OIDC_BASE_PATH}"

    private fun buildSubject(build: SRunningBuild): String {
        return "project:${build.projectId}:build_type:${build.buildTypeId}:ref:${getRef(build)}"
    }

    private fun getRef(build: SBuild): String {
        return build.branch?.name ?: build.branch?.displayName ?: "<default>"
    }

    private fun getRefType(build: SBuild): String {
        val ref = build.branch?.name ?: return "branch"
        return when {
            ref.startsWith("refs/tags/") -> "tag"
            ref.startsWith("refs/heads/") -> "branch"
            ref.startsWith("refs/pull/") -> "pull_request"
            ref.startsWith("refs/merge-requests/") -> "merge_request"
            else -> "branch"
        }
    }

    private fun calculateExpiry(build: SRunningBuild, now: Instant): Instant {
        val buildTimeout = build.buildType?.getOption(BuildTypeOptions.BT_EXECUTION_TIMEOUT)
        val timeoutSeconds = if (buildTimeout != null && buildTimeout > 0) {
            buildTimeout * 60L
        } else {
            OidcConstants.DEFAULT_TOKEN_LIFETIME_SECONDS
        }
        return now.plusSeconds(minOf(timeoutSeconds, OidcConstants.MAX_TOKEN_LIFETIME_SECONDS))
    }
}
