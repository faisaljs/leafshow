package com.leafshow.moviebox

import android.content.SharedPreferences
import android.util.Base64
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.lagradost.cloudstream3.*
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.ExtractorLinkType
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.newExtractorLink
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class MovieBoxProvider(
    private val sharedPref: SharedPreferences? = null
) : MainAPI() {

    override var mainUrl = HOST_POOL[4]
    override var name = "MovieBox"
    override val supportedTypes = setOf(TvType.Movie, TvType.TvSeries)
    override var lang = "en"
    override val hasMainPage = true

    override val mainPage = mainPageOf(
        "r|0|9167640870324258216" to "Trending Movies",
        "r|0|5692654647815587592" to "In Cinema",
        "r|0|414907768299210008" to "Bollywood",
        "r|0|3859721901924910512" to "South Indian",
        "r|0|8019599703232971616" to "Hollywood",
        "r|5|719331337777440448" to "Top Series",
        "r|5|4903182713986896328" to "Indian Drama",
        "1|1" to "Movies",
        "1|2" to "Series"
    )

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    private val siteHost = "moviebox.ph"
    private val apiPrefix = "/wefeed-h5api-bff"
    private val mapper = ObjectMapper()

    private val secretKeyDefault: ByteArray by lazy {
        Base64.decode("NzZpUmwwN3MweFNOOWpxbUVXQXQ3OUVCSnp1bElRSXNWNjRGWnIyTw==", Base64.DEFAULT)
    }
    private val secretKeyAlt: ByteArray by lazy {
        Base64.decode("WHFuMm5uTzQxL0w5Mm8xaXVYaFNMSFRiWHZZNFo1Wlo2Mm04bVNMQQ==", Base64.DEFAULT)
    }

    private val webUserAgent =
        "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36"

    private val mobileUserAgent =
        "com.community.mbox.in/50020131 (Linux; U; Android 14; en_IN; " +
                "Pixel 8; Build/UD1A.230803.041; Cronet/145.0.7582.0)"

    private val deviceId: String by lazy {
        val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        bytes.joinToString("") { "%02x".format(it) }
    }

    private val mobileClientInfo: String by lazy {
        val json = """{"package_name":"com.community.mbox.in","version_name":"4.0.03.0922.03","version_code":50020131,"os":"android","os_version":"14","device_id":"$deviceId","install_store":"official","gaid":"1b2212c1-dadf-43c3-a0c8-bd6ce48ae22d","brand":"Google","model":"Pixel 8","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}"""
        Base64.encodeToString(json.toByteArray(), Base64.NO_WRAP)
    }

    private val prefsKeyToken = "moviebox_bearer_token_v3"
    private val prefsKeyHost = "moviebox_host"

    @Volatile
    private var bearerToken: String? = null

    // ------------------------------------------------------------------
    // Crypto helpers
    // ------------------------------------------------------------------

    private fun md5(input: ByteArray): String =
        MessageDigest.getInstance("MD5").digest(input)
            .joinToString("") { "%02x".format(it) }

    private fun reverseString(s: String): String = s.reversed()

    private fun generateXClientToken(timestamp: Long = System.currentTimeMillis()): String {
        val ts = timestamp.toString()
        val hash = md5(reverseString(ts).toByteArray())
        return "$ts,$hash"
    }

    private fun buildCanonicalString(
        method: String,
        accept: String?,
        contentType: String?,
        url: String,
        body: String?,
        timestamp: Long
    ): String {
        val parsed = try { URI(url) } catch (_: Exception) { null }
        val path = parsed?.path ?: ""
        val rawQuery = parsed?.query ?: ""

        val query = if (rawQuery.isBlank()) "" else {
            rawQuery.split("&").mapNotNull { param ->
                val parts = param.split("=", limit = 2)
                if (parts.isEmpty()) null
                else parts[0] to (parts.getOrNull(1) ?: "")
            }.sortedBy { it.first }.joinToString("&") { "${it.first}=${it.second}" }
        }

        val canonicalUrl = if (query.isNotEmpty()) "$path?$query" else path

        val bodyBytes = body?.toByteArray()
        val bodyHash = bodyBytes?.let {
            val trimmed = if (it.size > 102400) it.copyOfRange(0, 102400) else it
            md5(trimmed)
        } ?: ""
        val bodyLength = bodyBytes?.size?.toString() ?: ""

        return buildString {
            append(method.toUpperCase(Locale.ROOT)).append('\n')
            append(accept ?: "").append('\n')
            append(contentType ?: "").append('\n')
            append(bodyLength).append('\n')
            append(timestamp).append('\n')
            append(bodyHash).append('\n')
            append(canonicalUrl)
        }
    }

    private fun generateXTrSignature(
        method: String,
        accept: String?,
        contentType: String?,
        url: String,
        body: String?,
        useAltKey: Boolean = false,
        timestamp: Long = System.currentTimeMillis()
    ): String {
        val canonical = buildCanonicalString(method, accept, contentType, url, body, timestamp)
        val secret = if (useAltKey) secretKeyAlt else secretKeyDefault
        val mac = Mac.getInstance("HmacMD5")
        mac.init(SecretKeySpec(secret, "HmacMD5"))
        val sig = Base64.encodeToString(mac.doFinal(canonical.toByteArray()), Base64.NO_WRAP)
        return "$timestamp|2|$sig"
    }

    // ------------------------------------------------------------------
    // JWT / token flow
    // ------------------------------------------------------------------

    private fun decodeJwtExpiry(token: String): Long {
        return try {
            val payload = token.split(".").getOrNull(1) ?: return 0L
            val padded = payload.replace('-', '+').replace('_', '/')
                .let { it + "=".repeat((4 - it.length % 4) % 4) }
            val json = String(Base64.decode(padded, Base64.DEFAULT))
            mapper.readTree(json).path("exp").asLong(0L)
        } catch (_: Exception) {
            0L
        }
    }

    private fun isTokenValid(token: String?): Boolean {
        if (token.isNullOrBlank()) return false
        return decodeJwtExpiry(token) > System.currentTimeMillis() / 1000 + 3600
    }

    private fun saveToken(token: String?) {
        if (token.isNullOrBlank() || !isTokenValid(token)) return
        bearerToken = token
        sharedPref?.edit()?.putString(prefsKeyToken, token)?.apply()
    }

    private fun loadSavedToken(): String? {
        val saved = sharedPref?.getString(prefsKeyToken, null)
        if (isTokenValid(saved)) {
            bearerToken = saved
            return saved
        }
        return null
    }

    private suspend fun fetchAnonymousToken(forceRefresh: Boolean = false): String? {
        if (!forceRefresh) {
            val cached = bearerToken ?: loadSavedToken()
            if (isTokenValid(cached)) return cached
        }

        val url = "$mainUrl$apiPrefix/home?host=$siteHost"
        val ts = System.currentTimeMillis()
        val accept = "application/json"
        val headers = mapOf(
            "User-Agent" to mobileUserAgent,
            "Accept" to accept,
            "Referer" to "https://$siteHost/",
            "Origin" to "https://$siteHost",
            "X-Client-Info" to mobileClientInfo,
            "X-Request-Lang" to "en",
            "X-Client-Token" to generateXClientToken(ts),
            "X-Tr-Signature" to generateXTrSignature("GET", accept, null, url, null, false, ts)
        )

        return try {
            val resp = app.get(url, headers = headers)
            val xUser = resp.headers["x-user"]
            if (!xUser.isNullOrBlank()) {
                val token = mapper.readTree(xUser).path("token").asText(null)
                saveToken(token)
                token
            } else null
        } catch (_: Exception) {
            null
        }
    }

    // ------------------------------------------------------------------
    // Request wrapper
    // ------------------------------------------------------------------

    private suspend fun api(
        path: String,
        params: Map<String, String> = emptyMap(),
        method: String = "GET",
        body: String? = null,
        useAltKey: Boolean = false,
        forceRefreshToken: Boolean = false
    ): JsonNode? {
        val allParams = linkedMapOf("host" to siteHost).apply { putAll(params) }
        val query = allParams.entries.joinToString("&") {
            "${it.key}=${java.net.URLEncoder.encode(it.value, "UTF-8").replace("+", "%20")}"
        }
        val url = "$mainUrl$apiPrefix$path?$query"

        val token = fetchAnonymousToken(forceRefreshToken)
        val accept = "application/json"
        val contentType = if (body != null) "application/json" else null
        val ts = System.currentTimeMillis()

        val headers = mutableMapOf(
            "User-Agent" to mobileUserAgent,
            "Accept" to accept,
            "Referer" to "https://$siteHost/",
            "Origin" to "https://$siteHost",
            "X-Client-Info" to mobileClientInfo,
            "X-Request-Lang" to "en",
            "X-Client-Token" to generateXClientToken(ts),
            "X-Tr-Signature" to generateXTrSignature(method, accept, contentType, url, body, useAltKey, ts)
        )
        if (!token.isNullOrBlank()) headers["Authorization"] = "Bearer $token"

        return runCatching {
            val text = if (method == "POST" && body != null) {
                app.post(url, headers = headers, json = mapper.readTree(body)).text
            } else {
                app.get(url, headers = headers).text
            }
            mapper.readTree(text)
        }.getOrNull()
    }

    // ------------------------------------------------------------------
    // Main page
    // ------------------------------------------------------------------

    override suspend fun getMainPage(page: Int, request: MainPageRequest): HomePageResponse {
        val key = request.data
        val (sortType, payload) = key.split("|").let {
            (it.getOrNull(0) ?: "1") to (it.getOrNull(1) ?: "1")
        }
        val extraParams = parseSectionExtras(key)

        val root = api(
            "/subject/filter",
            mapOf(
                "page" to page.toString(),
                "perPage" to "30",
                "sortType" to sortType,
                "subjectType" to payload
            ) + extraParams
        ) ?: return newHomePageResponse(request.name, emptyList())

        val items = collectSubjects(root.path("data"))
        return newHomePageResponse(request.name, items)
    }

    private fun parseSectionExtras(key: String): Map<String, String> {
        val out = mutableMapOf<String, String>()
        key.split(";").drop(1).forEach {
            val p = it.split("=", limit = 2)
            if (p.size == 2) out[p[0]] = p[1]
        }
        return out
    }

    // ------------------------------------------------------------------
    // Search
    // ------------------------------------------------------------------

    override suspend fun search(query: String): List<SearchResponse> {
        val root = api(
            "/subject/everyone-search",
            mapOf("keyword" to query, "page" to "1", "perPage" to "24")
        ) ?: return emptyList()

        return collectSubjects(root.path("data"))
    }

    private fun collectSubjects(node: JsonNode?): List<SearchResponse> {
        val out = LinkedHashMap<String, SearchResponse>()

        fun walk(n: JsonNode?) {
            if (n == null || n.isNull) return
            if (n.isArray) { n.forEach { walk(it) }; return }
            if (!n.isObject) return
            val id = n.path("subjectId").asText("")
            val title = n.path("title").asText("")
            if (id.isNotBlank() && title.isNotBlank()) {
                out[id] = toSearchResponse(n)
            } else {
                n.elements().forEach { walk(it) }
            }
        }
        walk(node)
        return out.values.toList()
    }

    private fun toSearchResponse(node: JsonNode): SearchResponse {
        val id = node.path("subjectId").asText()
        val title = node.path("title").asText()
        val detailPath = node.path("detailPath").asText("")
        val poster = node.path("cover").path("url").asText(null)
            ?: node.path("poster").path("url").asText(null)

        val type = when {
            node.path("subjectType").asInt(1) == 2 -> TvType.TvSeries
            node.path("seasons").isArray -> TvType.TvSeries
            else -> TvType.Movie
        }

        return newMovieSearchResponse(title, "$id|$detailPath", type) {
            this.posterUrl = poster
        }
    }

    // ------------------------------------------------------------------
    // Detail
    // ------------------------------------------------------------------

    override suspend fun load(url: String): LoadResponse? {
        val parts = url.split('|')
        val subjectId = parts.getOrNull(0).orEmpty()
        val detailPath = parts.getOrNull(1).orEmpty()
        if (subjectId.isBlank()) return null

        val root = api(
            "/subject/get-subject-detail",
            mapOf("subjectId" to subjectId, "detailPath" to detailPath)
        ) ?: return null

        val data = root.path("data")
        val subject = data.path("subject").takeIf { it.isObject } ?: data
        if (!subject.isObject) return null

        val title = subject.path("title").asText("Untitled")
        val poster = subject.path("cover").path("url").asText(null)
            ?: subject.path("poster").path("url").asText(null)
        val plot = subject.path("description").asText(null)
            ?: subject.path("synopsis").asText(null)
        val year = subject.path("releaseDate").asText("").take(4).toIntOrNull()
        val duration = (subject.path("duration").asInt(0) / 60).takeIf { it > 0 }

        val seasons = data.path("seasons").takeIf { it.isArray }
            ?: subject.path("seasons").takeIf { it.isArray }
            ?: data.path("resource").path("seasons").takeIf { it.isArray }

        val episodes = mutableListOf<Episode>()
        seasons?.forEachIndexed { si, season ->
            val seasonNum = season.path("se").asInt(si + 1)
            val epArr = season.path("episodes")
            if (!epArr.isArray) return@forEachIndexed
            epArr.forEachIndexed { ei, ep ->
                val epNum = ep.path("ep").asInt(ei + 1)
                val epId = ep.path("episodeId").asText("").ifBlank { ep.path("id").asText("") }
                episodes.add(
                    newEpisode("$subjectId|$detailPath|$seasonNum|$epNum|$epId") {
                        this.name = ep.path("title").asText("Episode $epNum")
                        this.season = seasonNum
                        this.episode = epNum
                        this.posterUrl = ep.path("cover").path("url").asText(null) ?: poster
                    }
                )
            }
        }

        return if (episodes.isNotEmpty()) {
            newTvSeriesLoadResponse(title, url, TvType.TvSeries, episodes) {
                this.posterUrl = poster
                this.plot = plot
                this.year = year
            }
        } else {
            newMovieLoadResponse(title, url, TvType.Movie, "$subjectId|$detailPath") {
                this.posterUrl = poster
                this.plot = plot
                this.year = year
                this.duration = duration
            }
        }
    }

    // ------------------------------------------------------------------
    // Play / links
    // ------------------------------------------------------------------

    private suspend fun fetchPlay(
        subjectId: String,
        detailPath: String,
        season: Int?,
        episode: Int?,
        episodeId: String?
    ): JsonNode? {
        val params = linkedMapOf(
            "subjectId" to subjectId,
            "detailPath" to detailPath,
            "resolution" to "720",
            "page" to "1"
        )
        if (season != null) params["se"] = season.toString()
        if (episode != null) params["ep"] = episode.toString()
        if (!episodeId.isNullOrBlank()) params["episodeId"] = episodeId

        return api("/subject/play", params)?.path("data")
    }

    override suspend fun loadLinks(
        data: String,
        isCasting: Boolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        val parts = data.split('|')
        val subjectId = parts.getOrNull(0).orEmpty()
        val detailPath = parts.getOrNull(1).orEmpty()
        val season = parts.getOrNull(2)?.toIntOrNull()
        val episode = parts.getOrNull(3)?.toIntOrNull()
        val episodeId = parts.getOrNull(4)
        if (subjectId.isBlank()) return false

        val playData = fetchPlay(subjectId, detailPath, season, episode, episodeId) ?: return false

        val streamNodes = mutableListOf<JsonNode>()
        playData.path("streams").takeIf { it.isArray }?.forEach { streamNodes.add(it) }
        playData.path("playInfo").takeIf { it.isArray }?.forEach { streamNodes.add(it) }
        playData.path("videos").takeIf { it.isArray }?.forEach { streamNodes.add(it) }
        if (streamNodes.isEmpty() && playData.isObject) {
            if (playData.path("videoUrl").asText("").isNotBlank()) streamNodes.add(playData)
        }

        var emitted = false

        for (stream in streamNodes) {
            val rawUrl = stream.path("url").asText("")
                .ifBlank { stream.path("playUrl").asText("") }
                .ifBlank { stream.path("streamUrl").asText("") }
                .ifBlank { stream.path("videoUrl").asText("") }
            if (rawUrl.isBlank()) continue

            val signCookie = stream.path("signCookie").asText(null)
                ?: stream.path("cookie").asText(null)

            val finalUrl = extractPolicyResource(signCookie) ?: rawUrl
            if (isDecoyStream(stream, finalUrl, rawUrl)) continue

            val resolution = stream.path("resolution").asInt(0)
                .takeIf { it > 0 }
                ?: stream.path("quality").asInt(0)

            val quality = when {
                resolution >= 1080 -> Qualities.P1080.value
                resolution >= 720 -> Qualities.P720.value
                resolution >= 480 -> Qualities.P480.value
                resolution >= 360 -> Qualities.P360.value
                else -> Qualities.Unknown.value
            }

            val streamHeaders = mutableMapOf(
                "User-Agent" to mobileUserAgent,
                "Accept" to "*/*",
                "Referer" to "https://$siteHost/",
                "Origin" to "https://$siteHost"
            )
            if (!signCookie.isNullOrBlank()) streamHeaders["Cookie"] = signCookie

            callback.invoke(
                newExtractorLink(
                    source = name,
                    name = if (resolution > 0) "$name ${resolution}p" else name,
                    url = finalUrl,
                    type = if (finalUrl.contains(".m3u8", true) || finalUrl.contains(".mpd", true))
                        ExtractorLinkType.M3U8 else ExtractorLinkType.M3U8
                ) {
                    this.referer = "https://$siteHost/"
                    this.quality = quality
                    this.headers = streamHeaders
                }
            )
            emitted = true
        }

        // Subtitles
        val subs = playData.path("subtitles").takeIf { it.isArray }
            ?: playData.path("captions").takeIf { it.isArray }
        subs?.forEach { sub ->
            val url = sub.path("url").asText("")
            if (url.isBlank()) return@forEach
            val lang = sub.path("language").asText("")
                .ifBlank { sub.path("lang").asText("") }
                .ifBlank { "Unknown" }
            subtitleCallback.invoke(SubtitleFile(lang, url))
        }

        return emitted
    }

    private fun isDecoyStream(stream: JsonNode, finalUrl: String, rawUrl: String): Boolean {
        if (finalUrl.contains("b164fbfb4347792950bdfbfb563d39d9", true)) return true
        val duration = stream.path("duration").asLong(0L)
        return duration in 1..299
    }

    private fun extractPolicyResource(signCookie: String?): String? {
        if (signCookie.isNullOrBlank()) return null

        // CloudFront-Policy=...
        val cf = Regex("CloudFront-Policy=([^;]+)").find(signCookie)
        if (cf != null) {
            val raw = cf.groupValues[1]
            val b64 = raw.replace('-', '+').replace('~', '/').replace('_', '=')
            val padded = b64 + "=".repeat((4 - b64.length % 4) % 4)
            try {
                val json = String(Base64.decode(padded, Base64.DEFAULT))
                val res = mapper.readTree(json).path("Statement").path(0).path("Resource").asText(null)
                if (res != null) {
                    val trimmed = res.trimEnd('*', '/')
                    return if (trimmed.endsWith(".mpd", true)) trimmed else "$trimmed/index.mpd"
                }
            } catch (_: Exception) { }
        }

        // Edge-Cache-Cookie=urlprefix=...
        val ec = Regex("Edge-Cache-Cookie=urlprefix=([^:;\\s]+)").find(signCookie)
        if (ec != null) {
            val b64 = ec.groupValues[1].replace('_', '/').replace('-', '+')
                .let { it + "=".repeat((4 - it.length % 4) % 4) }
            try {
                val decoded = String(Base64.decode(b64, Base64.DEFAULT)).trimEnd('/')
                return "$decoded/index.mpd"
            } catch (_: Exception) { }
        }

        return null
    }

    companion object {
        private val HOST_POOL = listOf(
            "https://api6.aoneroom.com",
            "https://api5.aoneroom.com",
            "https://api4.aoneroom.com",
            "https://api4sg.aoneroom.com",
            "https://api3.aoneroom.com"
        )
    }
}