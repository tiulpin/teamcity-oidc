package jetbrains.buildServer.oidc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import io.mockk.every
import io.mockk.mockk
import jetbrains.buildServer.serverSide.Branch
import jetbrains.buildServer.serverSide.BuildTypeOptions
import jetbrains.buildServer.serverSide.SBuildAgent
import jetbrains.buildServer.serverSide.SBuildType
import jetbrains.buildServer.serverSide.SProject
import jetbrains.buildServer.serverSide.SRunningBuild
import jetbrains.buildServer.serverSide.TriggeredBy
import jetbrains.buildServer.serverSide.WebLinks
import jetbrains.buildServer.users.SUser
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Date

class OidcTokenGeneratorTest {

    private lateinit var tokenGenerator: OidcTokenGenerator
    private lateinit var keyManager: OidcKeyManager
    private lateinit var webLinks: WebLinks
    private lateinit var rsaKey: RSAKey

    @BeforeEach
    fun setUp() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()

        rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID("test-key-id")
            .algorithm(JWSAlgorithm.RS256)
            .build()

        keyManager = mockk {
            every { getRsaKey() } returns rsaKey
            every { getKeyId() } returns "test-key-id"
        }

        webLinks = mockk {
            every { rootUrl } returns "https://teamcity.example.com/"
        }

        tokenGenerator = OidcTokenGenerator(keyManager, webLinks)
    }

    @Test
    fun `generateToken creates valid signed JWT`() {
        val build = createMockBuild()
        val audience = "sts.amazonaws.com"

        val token = tokenGenerator.generateToken(build, audience)

        val signedJwt = SignedJWT.parse(token)
        val verifier = RSASSAVerifier(rsaKey.toPublicJWK())

        assertThat(signedJwt.verify(verifier)).isTrue()
    }

    @Test
    fun `generateToken includes correct standard OIDC claims`() {
        val build = createMockBuild()
        val audience = "sts.amazonaws.com"

        val token = tokenGenerator.generateToken(build, audience)
        val claims = SignedJWT.parse(token).jwtClaimsSet

        assertThat(claims.issuer).isEqualTo("https://teamcity.example.com/app/oidc")
        assertThat(claims.audience).containsExactly(audience)
        assertThat(claims.subject).isEqualTo("project:TestProject:build_type:TestProject_Build:ref:refs/heads/main")
        assertThat(claims.jwtid).isNotNull
        assertThat(claims.issueTime).isNotNull()
        assertThat(claims.expirationTime).isAfter(Date.from(Instant.now()))
        assertThat(claims.notBeforeTime).isNotNull()
    }

    @Test
    fun `generateToken includes TeamCity build context claims`() {
        val build = createMockBuild()
        val audience = "sts.amazonaws.com"

        val token = tokenGenerator.generateToken(build, audience)
        val claims = SignedJWT.parse(token).jwtClaimsSet

        assertThat(claims.getStringClaim("project_id")).isEqualTo("TestProject")
        assertThat(claims.getStringClaim("project_name")).isEqualTo("Test Project")
        assertThat(claims.getStringClaim("build_type_id")).isEqualTo("TestProject_Build")
        assertThat(claims.getStringClaim("build_type_name")).isEqualTo("Build")
        assertThat(claims.getStringClaim("build_id")).isEqualTo("12345")
        assertThat(claims.getStringClaim("build_number")).isEqualTo("42")
        assertThat(claims.getStringClaim("ref")).isEqualTo("refs/heads/main")
        assertThat(claims.getStringClaim("ref_type")).isEqualTo("branch")
        assertThat(claims.getBooleanClaim("default_branch")).isTrue()
        assertThat(claims.getStringClaim("server_url")).isEqualTo("https://teamcity.example.com/app/oidc")
    }

    @Test
    fun `generateToken includes triggered_by when user available`() {
        val user = mockk<SUser> {
            every { username } returns "testuser"
        }
        val triggeredBy = mockk<TriggeredBy> {
            every { this@mockk.user } returns user
        }
        val build = createMockBuild(triggeredBy = triggeredBy)

        val token = tokenGenerator.generateToken(build, "test-audience")
        val claims = SignedJWT.parse(token).jwtClaimsSet

        assertThat(claims.getStringClaim("triggered_by")).isEqualTo("testuser")
    }

    @Test
    fun `generateToken includes agent_name when agent available`() {
        val agent = mockk<SBuildAgent> {
            every { name } returns "build-agent-1"
        }
        val build = createMockBuild(agent = agent)

        val token = tokenGenerator.generateToken(build, "test-audience")
        val claims = SignedJWT.parse(token).jwtClaimsSet

        assertThat(claims.getStringClaim("agent_name")).isEqualTo("build-agent-1")
    }

    @Test
    fun `generateToken sets correct ref_type for tags`() {
        val branch = mockk<Branch> {
            every { name } returns "refs/tags/v1.0.0"
            every { displayName } returns "v1.0.0"
            every { isDefaultBranch } returns false
        }
        val build = createMockBuild(branch = branch)

        val token = tokenGenerator.generateToken(build, "test-audience")
        val claims = SignedJWT.parse(token).jwtClaimsSet

        assertThat(claims.getStringClaim("ref_type")).isEqualTo("tag")
    }

    @Test
    fun `generateToken sets correct ref_type for pull requests`() {
        val branch = mockk<Branch> {
            every { name } returns "refs/pull/123/head"
            every { displayName } returns "PR #123"
            every { isDefaultBranch } returns false
        }
        val build = createMockBuild(branch = branch)

        val token = tokenGenerator.generateToken(build, "test-audience")
        val claims = SignedJWT.parse(token).jwtClaimsSet

        assertThat(claims.getStringClaim("ref_type")).isEqualTo("pull_request")
    }

    @Test
    fun `generateToken uses RS256 algorithm`() {
        val build = createMockBuild()

        val token = tokenGenerator.generateToken(build, "test-audience")
        val signedJwt = SignedJWT.parse(token)

        assertThat(signedJwt.header.algorithm).isEqualTo(JWSAlgorithm.RS256)
        assertThat(signedJwt.header.keyID).isEqualTo("test-key-id")
    }

    @Test
    fun `generateToken respects build timeout for expiry`() {
        val buildType = mockk<SBuildType> {
            every { project } returns mockk {
                every { name } returns "Test Project"
            }
            every { name } returns "Build"
            every { getOption(BuildTypeOptions.BT_EXECUTION_TIMEOUT) } returns 30 // 30 minutes
        }
        val build = createMockBuild(buildType = buildType)

        val token = tokenGenerator.generateToken(build, "test-audience")
        val claims = SignedJWT.parse(token).jwtClaimsSet

        val issuedAt = claims.issueTime.toInstant()
        val expiresAt = claims.expirationTime.toInstant()
        val tokenLifetime = java.time.Duration.between(issuedAt, expiresAt)

        // Should be approximately 30 minutes (1800 seconds)
        assertThat(tokenLifetime.seconds).isBetween(1790L, 1810L)
    }

    @Test
    fun `generateToken caps expiry at max lifetime`() {
        val buildType = mockk<SBuildType> {
            every { project } returns mockk {
                every { name } returns "Test Project"
            }
            every { name } returns "Build"
            every { getOption(BuildTypeOptions.BT_EXECUTION_TIMEOUT) } returns 300 // 5 hours - exceeds max
        }
        val build = createMockBuild(buildType = buildType)

        val token = tokenGenerator.generateToken(build, "test-audience")
        val claims = SignedJWT.parse(token).jwtClaimsSet

        val issuedAt = claims.issueTime.toInstant()
        val expiresAt = claims.expirationTime.toInstant()
        val tokenLifetime = java.time.Duration.between(issuedAt, expiresAt)

        // Should be capped at 2 hours (7200 seconds)
        assertThat(tokenLifetime.seconds).isLessThanOrEqualTo(OidcConstants.MAX_TOKEN_LIFETIME_SECONDS)
    }

    @Test
    fun `getIssuer removes trailing slash from root URL`() {
        every { webLinks.rootUrl } returns "https://teamcity.example.com/"

        assertThat(tokenGenerator.getIssuer()).isEqualTo("https://teamcity.example.com/app/oidc")
    }

    @Test
    fun `getIssuer handles root URL without trailing slash`() {
        every { webLinks.rootUrl } returns "https://teamcity.example.com"

        assertThat(tokenGenerator.getIssuer()).isEqualTo("https://teamcity.example.com/app/oidc")
    }

    private fun createMockBuild(
        branch: Branch? = null,
        buildType: SBuildType? = null,
        triggeredBy: TriggeredBy? = null,
        agent: SBuildAgent? = null
    ): SRunningBuild {
        val defaultBranch = branch ?: mockk {
            every { name } returns "refs/heads/main"
            every { displayName } returns "main"
            every { isDefaultBranch } returns true
        }

        val defaultProject = mockk<SProject> {
            every { name } returns "Test Project"
        }

        val defaultBuildType = buildType ?: mockk {
            every { project } returns defaultProject
            every { name } returns "Build"
            every { getOption(BuildTypeOptions.BT_EXECUTION_TIMEOUT) } returns 60 // 1 hour
        }

        val defaultTriggeredBy = triggeredBy ?: mockk {
            every { user } returns null
        }

        val defaultAgent = agent ?: mockk {
            every { name } returns "Default Agent"
        }

        return mockk {
            every { buildId } returns 12345L
            every { buildNumber } returns "42"
            every { projectId } returns "TestProject"
            every { buildTypeId } returns "TestProject_Build"
            every { this@mockk.branch } returns defaultBranch
            every { this@mockk.buildType } returns defaultBuildType
            every { this@mockk.triggeredBy } returns defaultTriggeredBy
            every { this@mockk.agent } returns defaultAgent
        }
    }
}
