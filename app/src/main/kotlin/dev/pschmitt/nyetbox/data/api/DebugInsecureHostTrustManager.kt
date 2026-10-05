package dev.pschmitt.nyetbox.data.api

import java.net.Socket
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager
import timber.log.Timber

/**
 * TEMPORARY, debug builds only: if normal certificate validation fails for one of [insecureHosts],
 * accept the connection anyway (logging a warning). Every other host is still fully validated.
 *
 * This disables protection against impersonation of those hosts - anyone able to intercept the
 * connection could read the API token. Remove once the server's certificate chain is fixed.
 */
class DebugInsecureHostTrustManager(
    private val delegate: X509TrustManager,
    private val insecureHosts: Set<String>,
) : X509ExtendedTrustManager() {

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkClientTrusted(chain, authType)

    override fun checkClientTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        socket: Socket?,
    ) = delegate.checkClientTrusted(chain, authType)

    override fun checkClientTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        engine: SSLEngine?,
    ) = delegate.checkClientTrusted(chain, authType)

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkServerTrusted(chain, authType)

    override fun checkServerTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        socket: Socket?,
    ) = check(chain, authType, (socket as? SSLSocket)?.handshakeSession?.peerHost)

    override fun checkServerTrusted(
        chain: Array<X509Certificate>,
        authType: String,
        engine: SSLEngine?,
    ) = check(chain, authType, engine?.peerHost)

    private fun check(chain: Array<X509Certificate>, authType: String, host: String?) {
        try {
            delegate.checkServerTrusted(chain, authType)
        } catch (e: CertificateException) {
            if (host == null || host.lowercase() !in insecureHosts) throw e
            Timber.w(e, "Accepting untrusted certificate for %s (debug override)", host)
        }
    }
}
