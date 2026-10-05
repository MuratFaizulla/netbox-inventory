package dev.pschmitt.nyetbox.data.api

import dev.pschmitt.nyetbox.BuildConfig
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import timber.log.Timber

/**
 * Platform trust manager that, when a server sends an incomplete chain (leaf without its
 * intermediate), downloads the missing issuer from the certificate's Authority Information Access
 * "CA Issuers" URL and retries validation - the same thing Chrome does, which is why such servers
 * open fine in a browser but fail in apps with "Trust anchor for certification path not found".
 *
 * Validation itself is unchanged: the downloaded certificates are untrusted input that only helps
 * build the path, which still has to end at a platform (or network-security-config) trust anchor.
 */
class AiaFetchingTrustManager(private val delegate: X509TrustManager) : X509TrustManager {

    private val fetched = ConcurrentHashMap<String, List<X509Certificate>>()

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkClientTrusted(chain, authType)

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        try {
            delegate.checkServerTrusted(chain, authType)
        } catch (original: CertificateException) {
            var extended = chain.toList()
            repeat(MAX_FETCHES) {
                val last = extended.last()
                if (last.subjectX500Principal == last.issuerX500Principal) throw original
                val url = caIssuersUrl(last) ?: throw original
                // Only successful downloads are cached, so a transient failure can be retried.
                val downloaded =
                    fetched[url] ?: download(url).also { if (it.isNotEmpty()) fetched[url] = it }
                val issuers = downloaded.filterNot { it in extended }
                if (issuers.isEmpty()) throw original
                extended = extended + issuers
                try {
                    delegate.checkServerTrusted(extended.toTypedArray(), authType)
                    return
                } catch (ignored: CertificateException) {
                    // Still incomplete - try the next level up.
                }
            }
            throw original
        }
    }

    private fun download(url: String): List<X509Certificate> =
        try {
            val connection = URL(url).openConnection() as HttpURLConnection
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            try {
                connection.inputStream.use { stream ->
                    CertificateFactory.getInstance("X.509")
                        .generateCertificates(stream)
                        .filterIsInstance<X509Certificate>()
                }
            } finally {
                connection.disconnect()
            }
        } catch (e: Exception) {
            Timber.w(e, "Unable to fetch issuer certificate from %s", url)
            emptyList()
        }

    companion object {
        private const val MAX_FETCHES = 2
        private const val TIMEOUT_MS = 10_000

        // id-ad-caIssuers (1.3.6.1.5.5.7.48.2) followed by a [6] uniformResourceIdentifier.
        private val CA_ISSUERS_OID =
            byteArrayOf(0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02)
        private const val AIA_EXTENSION_OID = "1.3.6.1.5.5.7.1.1"
        private const val URI_TAG = 0x86.toByte()

        /** Socket factory + trust manager pair for OkHttp's `sslSocketFactory(...)`. */
        fun create(): Pair<SSLSocketFactory, X509TrustManager> {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(null as KeyStore?)
            val platform = factory.trustManagers.filterIsInstance<X509TrustManager>().first()
            val aia = AiaFetchingTrustManager(platform)
            // TEMPORARY: see DebugInsecureHostTrustManager - debug builds only, one host only.
            val trustManager =
                if (BuildConfig.DEBUG) {
                    DebugInsecureHostTrustManager(aia, setOf("web-netbox.t-cloud.kz"))
                } else {
                    aia
                }
            val context = SSLContext.getInstance("TLS")
            context.init(null, arrayOf(trustManager), null)
            return context.socketFactory to trustManager
        }

        internal fun caIssuersUrl(certificate: X509Certificate): String? {
            val value = certificate.getExtensionValue(AIA_EXTENSION_OID) ?: return null
            var i = 0
            while (i <= value.size - CA_ISSUERS_OID.size - 2) {
                if (
                    value.matchesAt(i, CA_ISSUERS_OID) && value[i + CA_ISSUERS_OID.size] == URI_TAG
                ) {
                    val lengthIndex = i + CA_ISSUERS_OID.size + 1
                    val length = value[lengthIndex].toInt() and 0xFF
                    // Short-form DER lengths only - AIA URLs are always well under 128 bytes.
                    if (length >= 0x80 || lengthIndex + 1 + length > value.size) return null
                    val url = String(value, lengthIndex + 1, length, Charsets.US_ASCII)
                    if (url.startsWith("http://") || url.startsWith("https://")) return url
                }
                i++
            }
            return null
        }

        private fun ByteArray.matchesAt(offset: Int, pattern: ByteArray): Boolean =
            pattern.indices.all { this[offset + it] == pattern[it] }
    }
}
