package dev.pschmitt.nyetbox.di

import android.content.Context
import coil3.ImageLoader
import coil3.decode.BitmapFactoryDecoder
import coil3.network.okhttp.OkHttpNetworkFetcherFactory
import coil3.serviceLoaderEnabled
import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.pschmitt.nyetbox.BuildConfig
import dev.pschmitt.nyetbox.data.api.AiaFetchingTrustManager
import dev.pschmitt.nyetbox.data.api.AuthInterceptor
import dev.pschmitt.nyetbox.data.api.DynamicBaseUrlInterceptor
import dev.pschmitt.nyetbox.data.api.GenericNetBoxApi
import dev.pschmitt.nyetbox.data.api.MediaNetBoxApi
import dev.pschmitt.nyetbox.data.api.NetBoxApi
import dev.pschmitt.nyetbox.data.api.OfflineModeInterceptor
import dev.pschmitt.nyetbox.data.api.TopologyApi
import dev.pschmitt.nyetbox.data.repository.FileDownloadRepository
import dev.pschmitt.nyetbox.image.LibavifImageDecoder
import dev.pschmitt.nyetbox.image.LocalFileFetcher
import dev.pschmitt.nyetbox.image.PersistentCacheFetcher
import javax.inject.Qualifier
import javax.inject.Singleton
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit

/**
 * OkHttpClient for requests against URLs NetBox itself already returned in full (media/document
 * URLs) - skips [DynamicBaseUrlInterceptor], which would otherwise re-prepend the configured base
 * URL's path onto an already-complete, already-correct URL (double-prefixing it if the instance is
 * reverse-proxied under a subpath). Still carries [AuthInterceptor] - NetBox media commonly
 * requires the API token too, confirmed against a real instance (unauthenticated media requests 302
 * to the login page).
 */
@Qualifier @Retention(AnnotationRetention.BINARY) annotation class DownloadClient

@Qualifier @Retention(AnnotationRetention.BINARY) annotation class NewsClient

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    // Shared by every client that talks to the user's NetBox instance, so servers that omit their
    // intermediate certificate still validate (see AiaFetchingTrustManager).
    private val tls by lazy { AiaFetchingTrustManager.create() }

    @Provides
    @Singleton
    fun provideJson(): Json = Json {
        ignoreUnknownKeys = true
        isLenient = true
        explicitNulls = false
    }

    @Provides
    @Singleton
    fun provideMediaNetBoxApi(retrofit: Retrofit): MediaNetBoxApi =
        retrofit.create(MediaNetBoxApi::class.java)

    @Provides
    @Singleton
    fun provideOkHttpClient(
        dynamicBaseUrlInterceptor: DynamicBaseUrlInterceptor,
        authInterceptor: AuthInterceptor,
    ): OkHttpClient {
        val logging =
            HttpLoggingInterceptor().apply {
                level =
                    if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BASIC
                    else HttpLoggingInterceptor.Level.NONE
            }
        return OkHttpClient.Builder()
            .sslSocketFactory(tls.first, tls.second)
            // Rewrites scheme/host/path to the configured instance - added first so auth/logging
            // see the real request.
            .addInterceptor(dynamicBaseUrlInterceptor)
            .addInterceptor(authInterceptor)
            .addInterceptor(logging)
            .build()
    }

    @Provides
    @Singleton
    @DownloadClient
    fun provideDownloadOkHttpClient(
        authInterceptor: AuthInterceptor,
        offlineModeInterceptor: OfflineModeInterceptor,
    ): OkHttpClient {
        val logging =
            HttpLoggingInterceptor().apply {
                level =
                    if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BASIC
                    else HttpLoggingInterceptor.Level.NONE
            }
        return OkHttpClient.Builder()
            .sslSocketFactory(tls.first, tls.second)
            .addInterceptor(offlineModeInterceptor)
            .addInterceptor(authInterceptor)
            .addInterceptor(logging)
            .build()
    }

    @Provides
    @Singleton
    @NewsClient
    fun provideNewsClient(): OkHttpClient =
        OkHttpClient.Builder().callTimeout(15, java.util.concurrent.TimeUnit.SECONDS).build()

    @Provides
    @Singleton
    fun provideRetrofit(okHttpClient: OkHttpClient, json: Json): Retrofit =
        Retrofit.Builder()
            // Placeholder - DynamicBaseUrlInterceptor rewrites every request to the configured
            // NetBox instance at request time, so this host is never actually contacted.
            .baseUrl("http://netbox.invalid/")
            .client(okHttpClient)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()

    @Provides
    @Singleton
    fun provideNetBoxApi(retrofit: Retrofit): NetBoxApi = retrofit.create(NetBoxApi::class.java)

    @Provides
    @Singleton
    fun provideGenericNetBoxApi(retrofit: Retrofit): GenericNetBoxApi =
        retrofit.create(GenericNetBoxApi::class.java)

    @Provides
    @Singleton
    fun provideTopologyApi(retrofit: Retrofit): TopologyApi =
        retrofit.create(TopologyApi::class.java)

    // Device-type stock photos and image-attachment URLs are already-absolute NetBox media URLs,
    // same category as the download client above - reuses it rather than the
    // DynamicBaseUrlInterceptor-
    // wrapped API client, so a subpath-hosted instance doesn't get its media path double-prefixed.
    @Provides
    @Singleton
    fun provideImageLoader(
        @ApplicationContext context: Context,
        @DownloadClient okHttpClient: OkHttpClient,
        fileDownloadRepository: FileDownloadRepository,
    ): ImageLoader =
        ImageLoader.Builder(context)
            // Keep Coil's platform file/URI mappers and fetchers available in debug and release;
            // the custom registry below only adds NetBox authentication and AVIF support.
            .serviceLoaderEnabled(true)
            .components {
                add(LocalFileFetcher.Factory())
                // Ahead of the network fetcher so a cached NetBox media URL resolves to its
                // offline copy without ever hitting the network - see PersistentCacheFetcher's
                // kdoc for why this replaced synchronous per-row lookups in list composables.
                add(PersistentCacheFetcher.Factory(fileDownloadRepository))
                add(LibavifImageDecoder.Factory())
                // The app uses coil-core directly through Compose. Register the standard Android
                // decoder explicitly so cached PNG/JPEG images work even when service-loader
                // components are unavailable on older devices.
                add(BitmapFactoryDecoder.Factory())
                add(OkHttpNetworkFetcherFactory(callFactory = { okHttpClient }))
            }
            .build()
}
