package com.leafshow.moviebox

import android.net.Uri
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.lagradost.cloudstream3.*
import com.lagradost.cloudstream3.LoadResponse.Companion.addImdbId
import com.lagradost.cloudstream3.LoadResponse.Companion.addTMDbId
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.ExtractorLinkType
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.newExtractorLink
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class MovieBoxProvider : MainAPI() {

    // ------------------------------------------------------------------
    // Provider identity
    // ------------------------------------------------------------------

    override var mainUrl = "https://api3.aoneroom.com"
    override var name = "MovieBox"
    override val hasMainPage = true
    override var lang = "hi"
    override val supportedTypes = setOf(TvType.Movie, TvType.TvSeries)

    // ------------------------------------------------------------------
    // Signing keys — base64-encoded HMAC secrets shipped in the mobile app
    // ------------------------------------------------------------------

    private val hmacKeyPrimary = base64Decode(
        "NzZpUmwwN3MweFNOOWpxbUVXQXQ3OUVCSlp1bElRSXNWNjRGWnIyTw=="
    )
    private val hmacKeySecondary = base64Decode(
        "WHFuMm5uTzQxL0w5Mm8xaXVYaFNMSFRiWHZZNFo1Wlo2Mm04bVNMQQ=="
    )

    // ------------------------------------------------------------------
    // Stable device identity — generated once per provider instance
    // ------------------------------------------------------------------

    private val deviceId: String = ByteArray(16)
        .also { SecureRandom().nextBytes(it) }
        .joinToString("") { "%02x".format(it) }

    private val rng = SecureRandom()

    private data class DeviceProfile(val brand: String, val model: String)

    private val devicePool = mapOf(
        "google" to listOf("Pixel 6", "Pixel 7", "Pixel 8"),
        "samsung" to listOf("SM-S918B", "SM-A528B"),
        "xiaomi" to listOf("2201117TI", "M2012K11AI"),
        "oneplus" to listOf("LE2111", "CPH2449")
    )

    private fun randomDevice(): DeviceProfile {
        val brand = devicePool.keys.elementAt(rng.nextInt(devicePool.size))
        val models = devicePool.getValue(brand)
        return DeviceProfile(brand, models[rng.nextInt(models.size)])
    }

    // ------------------------------------------------------------------
    // HMAC request signing
    // ------------------------------------------------------------------

    private fun md5Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("MD5").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    private fun buildXClientToken(ts: Long = System.currentTimeMillis()): String {
        val raw = ts.toString()
        val digest = md5Hex(raw.reversed().toByteArray(Charsets.UTF_8))
        return "$raw,$digest"
    }

    private fun buildCanonicalString(
        method: String,
        accept: String?,
        contentType: String?,
        url: String,
        body: String?,
        timestamp: Long
    ): String {
        val parsed = Uri.parse(url)
        val path = parsed.path ?: ""

        // Query parameters sorted lexicographically, values kept raw
        val query = if (parsed.queryParameterNames.isNotEmpty()) {
            parsed.queryParameterNames.sorted().joinToString("&") { key ->
                parsed.getQueryParameters(key).joinToString("&") { value ->
                    "$key=$value"
                }
            }
        } else ""

        val canonicalUrl = if (query.isNotEmpty()) "$path?$query" else path

        val bodyBytes = body?.toByteArray(Charsets.UTF_8)
        val bodyHash = bodyBytes?.let {
            val head = if (it.size > 102_400) it.copyOfRange(0, 102_400) else it
            md5Hex(head)
        } ?: ""

        val bodyLength = bodyBytes?.size?.toString() ?: ""

        return buildString {
            append(method.uppercase()).append('\n')
            append(accept ?: "").append('\n')
            append(contentType ?: "").append('\n')
            append(bodyLength).append('\n')
            append(timestamp).append('\n')
            append(bodyHash).append('\n')
            append(canonicalUrl)
        }
    }

    private fun buildXTrSignature(
        method: String,
        accept: String?,
        contentType: String?,
        url: String,
        body: String? = null,
        useSecondaryKey: Boolean = false,
        timestamp: Long = System.currentTimeMillis()
    ): String {
        val canonical = buildCanonicalString(method, accept, contentType, url, body, timestamp)
        val secret = base64DecodeArray(if (useSecondaryKey) hmacKeySecondary else hmacKeyPrimary)

        val mac = Mac.getInstance("HmacMD5")
        mac.init(SecretKeySpec(secret, "HmacMD5"))
        val signature = base64Encode(mac.doFinal(canonical.toByteArray(Charsets.UTF_8)))

        return "$timestamp|2|$signature"
    }

    // ------------------------------------------------------------------
    // Client identity headers
    // ------------------------------------------------------------------

    private fun mobileClientInfo(profile: DeviceProfile): String {
        return """{"package_name":"com.community.mbox.in","version_name":"3.0.03.0529.03","version_code":50020042,"os":"android","os_version":"16","device_id":"$deviceId","install_store":"ps","gaid":"d7578036d13336cc","brand":"${profile.brand}","model":"${profile.model}","system_language":"en","net":"NETWORK_WIFI","region":"IN","timezone":"Asia/Calcutta","sp_code":""}"""
    }

    private val mobileUserAgent =
        "com.community.mbox.in/50020042 (Linux; U; Android 16; en_IN; sdk_gphone64_x86_64; " +
                "Build/BP22.250325.006; Cronet/133.0.6876.3)"

    private fun authHeaders(
        url: String,
        method: String = "GET",
        body: String? = null,
        token: String? = null,
        profile: DeviceProfile = randomDevice()
    ): Map<String, String> {
        val ts = System.currentTimeMillis()
        val accept = "application/json"
        val contentType = if (body != null) "application/json; charset=utf-8" else "application/json"

        val map = mutableMapOf(
            "user-agent" to mobileUserAgent,
            "accept" to accept,
            "content-type" to contentType,
            "connection" to "keep-alive",
            "x-client-token" to buildXClientToken(ts),
            "x-tr-signature" to buildXTrSignature(method, accept, contentType, url, body, timestamp = ts),
            "x-client-info" to mobileClientInfo(profile),
            "x-client-status" to "0"
        )
        if (!token.isNullOrBlank()) map["Authorization"] = "Bearer $token"
        return map
    }

    // ------------------------------------------------------------------
    // Home page
    // ------------------------------------------------------------------

    override val mainPage = mainPageOf(
        "4516404531735022304" to "Trending",
        "5692654647815587592" to "In Cinema",
        "414907768299210008" to "Bollywood",
        "3859721901924910512" to "South Indian",
        "8019599703232971616" to "Hollywood",
        "4741626294545400336" to "Top Series",
        "8434602210994128512" to "Anime",
        "4903182713986896328" to "Indian Drama",
        "7878715743607948784" to "Korean Drama",
        "1|1" to "All Movies",
        "1|2" to "All Series",
        "1|1;country=India" to "Indian Movies",
        "1|2;country=India" to "Indian Series",
        "1|1;country=Korea" to "Korean Movies",
        "1|2;country=Korea" to "Korean Series"
    )

    override suspend fun getMainPage(page: Int, request: MainPageRequest): HomePageResponse {
        val spec = request.data
        val perPage = 15

        // Filter mode: "1|1;country=India"
        if (spec.contains("|")) {
            val url = "$mainUrl/wefeed-mobile-bff/subject-api/list"
            val (channelId, extras) = parseFilterSpec(spec)
            val json = buildFilterJson(page, perPage, channelId, extras)

            val response = app.post(
                url,
                headers = authHeaders(url, method = "POST", body = json),
                requestBody = json.toRequestBody("application/json".toMediaType())
            )
            return parseSubjectList(response.text, request.name)
        }

        // Ranking mode: tab id
        val url = "$mainUrl/wefeed-mobile-bff/tab/ranking-list?" +
                "tabId=0&categoryType=$spec&page=$page&perPage=$perPage"
        val response = app.get(url, headers = authHeaders(url))
        return parseSubjectList(response.text, request.name)
    }

    private fun parseFilterSpec(spec: String): Pair<String?, Map<String, String>> {
        val head = spec.substringBefore(";").split("|")
        val channelId = head.getOrNull(1)
        val extras = spec.substringAfter(";", "")
            .split(";")
            .mapNotNull {
                val parts = it.split("=", limit = 2)
                if (parts.size == 2) parts[0] to parts[1] else null
            }
            .toMap()
        return channelId to extras
    }

    private fun buildFilterJson(
        page: Int,
        perPage: Int,
        channelId: String?,
        extras: Map<String, String>
    ): String {
        fun v(key: String) = extras[key] ?: "All"
        return """{"page":$page,"perPage":$perPage,"channelId":"$channelId","classify":"${v("classify")}","country":"${v("country")}","year":"${v("year")}","genre":"${v("genre")}","sort":"${extras["sort"] ?: "ForYou"}"}"""
    }

    private fun parseSubjectList(raw: String, sectionName: String): HomePageResponse {
        val mapper = jacksonObjectMapper()
        val items = try {
            val root = mapper.readTree(raw)
            root["data"]?.get("items")
                ?: root["data"]?.get("subjects")
                ?: return newHomePageResponse(emptyList())
        } catch (_: Exception) {
            return newHomePageResponse(emptyList())
        }

        val list = items.mapNotNull { node ->
            val id = node["subjectId"]?.asText() ?: return@mapNotNull null
            val title = node["title"]?.asText()?.substringBefore("[") ?: return@mapNotNull null
            val poster = node["cover"]?.get("url")?.asText()
            val type = subjectTypeToTvType(node["subjectType"]?.asInt() ?: 1)

            newMovieSearchResponse(title, id, type) {
                this.posterUrl = poster
                this.score = Score.from10(node["imdbRatingValue"]?.asText())
            }
        }

        return newHomePageResponse(listOf(HomePageList(sectionName, list)))
    }

    private fun subjectTypeToTvType(code: Int): TvType = when (code) {
        2, 7 -> TvType.TvSeries
        else -> TvType.Movie
    }

    // ------------------------------------------------------------------
    // Search
    // ------------------------------------------------------------------

    override suspend fun search(query: String, page: Int): SearchResponseList {
        val url = "$mainUrl/wefeed-mobile-bff/subject-api/search/v2"
        val json = """{"page":$page,"perPage":20,"keyword":${JSONObject.quote(query)}}"""

        val response = try {
            app.post(
                url,
                headers = authHeaders(url, method = "POST", body = json),
                requestBody = json.toRequestBody("application/json".toMediaType())
            )
        } catch (_: Exception) {
            return newSearchResponseList(emptyList())
        }

        val mapper = jacksonObjectMapper()
        val results = try {
            mapper.readTree(response.text)["data"]?.get("results")
                ?: return newSearchResponseList(emptyList())
        } catch (_: Exception) {
            return newSearchResponseList(emptyList())
        }

        val out = mutableListOf<SearchResponse>()
        for (group in results) {
            val subjects = group["subjects"] ?: continue
            for (node in subjects) {
                val id = node["subjectId"]?.asText() ?: continue
                val title = node["title"]?.asText() ?: continue
                val poster = node["cover"]?.get("url")?.asText()
                val type = subjectTypeToTvType(node["subjectType"]?.asInt() ?: 1)

                out.add(
                    newMovieSearchResponse(title, id, type) {
                        this.posterUrl = poster
                        this.score = Score.from10(node["imdbRatingValue"]?.asText())
                    }
                )
            }
        }
        return out.toNewSearchResponseList()
    }

    // ------------------------------------------------------------------
    // Detail
    // ------------------------------------------------------------------

    override suspend fun load(url: String): LoadResponse {
        val subjectId = extractSubjectId(url)
        val detailUrl = "$mainUrl/wefeed-mobile-bff/subject-api/get?subjectId=$subjectId"

        val response = app.get(detailUrl, headers = authHeaders(detailUrl))
        if (response.code != 200) throw ErrorLoadingException("detail request failed: ${response.code}")

        val mapper = jacksonObjectMapper()
        val data = try {
            mapper.readTree(response.text)["data"]
        } catch (_: Exception) {
            null
        } ?: throw ErrorLoadingException("empty detail payload")

        val title = data["title"]?.asText()?.substringBefore("[")
            ?: throw ErrorLoadingException("missing title")
        val type = subjectTypeToTvType(data["subjectType"]?.asInt() ?: 1)

        val description = data["description"]?.asText()
        val releaseDate = data["releaseDate"]?.asText()
        val year = releaseDate?.take(4)?.toIntOrNull()
        val durationMinutes = parseDurationMinutes(data["duration"]?.asText())
        val genres = data["genre"]?.asText()
            ?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() }
            ?: emptyList()

        val coverUrl = data["cover"]?.get("url")?.asText()
        val imdbRating = data["imdbRatingValue"]?.asText()?.toDoubleOrNull()

        val actors = data["staffList"]?.mapNotNull { staff ->
            if (staff["staffType"]?.asInt() != 1) return@mapNotNull null
            val actorName = staff["name"]?.asText() ?: return@mapNotNull null
            val character = staff["character"]?.asText()
            val avatar = staff["avatarUrl"]?.asText()
            ActorData(Actor(actorName, avatar), roleString = character)
        }?.distinctBy { it.actor.name } ?: emptyList()

        // Enrichment: TMDB id, IMDb id, Cinemeta metadata, logo
        val (tmdbId, imdbId) = identifyOnTmdb(title, year, imdbRating)
        val meta = imdbId?.let { fetchCinemeta(it, type) }
        val logo = fetchTmdbLogo(tmdbId, type)

        val poster = meta?.get("poster")?.asText() ?: coverUrl
        val background = meta?.get("background")?.asText() ?: coverUrl
        val plot = meta?.get("overview")?.asText() ?: description
        val imdbScore = meta?.get("imdbRating")?.asText()

        val score = Score.from10(imdbScore) ?: imdbRating?.let { Score.from10(it) }

        if (type == TvType.TvSeries) {
            val episodes = collectEpisodes(subjectId, data, meta, poster)
            return newTvSeriesLoadResponse(title, detailUrl, type, episodes) {
                this.posterUrl = poster
                this.backgroundPosterUrl = background
                if (!logo.isNullOrBlank()) this.logoUrl = logo
                this.plot = plot
                this.year = year
                this.tags = genres
                this.actors = actors
                this.score = score
                this.duration = durationMinutes
                addImdbId(imdbId)
                if (tmdbId != null) addTMDbId(tmdbId.toString())
            }
        }

        return newMovieLoadResponse(title, detailUrl, type, subjectId) {
            this.posterUrl = poster
            this.backgroundPosterUrl = background
            if (!logo.isNullOrBlank()) this.logoUrl = logo
            this.plot = plot
            this.year = year
            this.tags = genres
            this.actors = actors
            this.score = score
            this.duration = durationMinutes
            addImdbId(imdbId)
            if (tmdbId != null) addTMDbId(tmdbId.toString())
        }
    }

    private fun extractSubjectId(raw: String): String =
        Regex("""subjectId=([^&]+)""").find(raw)?.groupValues?.get(1)
            ?: raw.substringAfterLast('/')

    private fun parseDurationMinutes(text: String?): Int? {
        if (text.isNullOrBlank()) return null
        val match = Regex("""(\d+)h\s*(\d+)m""").find(text)
        if (match != null) {
            val h = match.groupValues[1].toIntOrNull() ?: 0
            val m = match.groupValues[2].toIntOrNull() ?: 0
            return h * 60 + m
        }
        return text.replace("m", "").trim().toIntOrNull()
    }

    private suspend fun collectEpisodes(
        subjectId: String,
        detail: JsonNode,
        meta: JsonNode?,
        fallbackPoster: String?
    ): List<Episode> {
        // Gather every dubbed variant's subject id so we can union season/episode numbers
        val subjectIds = mutableListOf(subjectId)
        detail["dubs"]?.forEach { dub ->
            dub["subjectId"]?.asText()?.takeIf { it.isNotBlank() && it !in subjectIds }
                ?.let { subjectIds.add(it) }
        }

        val seasonMap = mutableMapOf<Int, MutableSet<Int>>()
        val mapper = jacksonObjectMapper()

        for (sid in subjectIds) {
            val seasonUrl = "$mainUrl/wefeed-mobile-bff/subject-api/season-info?subjectId=$sid"
            val response = try {
                app.get(seasonUrl, headers = authHeaders(seasonUrl))
            } catch (_: Exception) {
                continue
            }
            if (response.code != 200) continue

            val seasons = try {
                mapper.readTree(response.text)["data"]?.get("seasons")
            } catch (_: Exception) {
                null
            } ?: continue

            for (season in seasons) {
                val number = season["se"]?.asInt() ?: 1
                val maxEp = season["maxEp"]?.asInt() ?: 1
                val bucket = seasonMap.getOrPut(number) { mutableSetOf() }
                (1..maxEp).forEach { bucket.add(it) }
            }
        }

        val metaVideos = meta?.get("videos")?.toList() ?: emptyList()
        val episodes = mutableListOf<Episode>()

        seasonMap.toSortedMap().forEach { (season, epSet) ->
            epSet.sorted().forEach { episode ->
                val metaEp = metaVideos.firstOrNull {
                    it["season"]?.asInt() == season && it["episode"]?.asInt() == episode
                }

                val epName = metaEp?.get("name")?.asText()?.takeIf { it.isNotBlank() }
                    ?: "S${season}E${episode}"
                val epPlot = metaEp?.get("overview")?.asText()
                val epThumb = metaEp?.get("thumbnail")?.asText()?.takeIf { it.isNotBlank() }
                    ?: fallbackPoster
                val runtime = metaEp?.get("runtime")?.asText()?.filter { it.isDigit() }?.toIntOrNull()
                val aired = metaEp?.get("released")?.asText()

                episodes.add(
                    newEpisode("$subjectId|$season|$episode") {
                        this.name = epName
                        this.season = season
                        this.episode = episode
                        this.posterUrl = epThumb
                        this.description = epPlot
                        this.runTime = runtime
                        if (!aired.isNullOrBlank()) addDate(aired)
                    }
                )
            }
        }

        if (episodes.isEmpty()) {
            episodes.add(
                newEpisode("$subjectId|1|1") {
                    this.name = "Episode 1"
                    this.season = 1
                    this.episode = 1
                    this.posterUrl = fallbackPoster
                }
            )
        }
        return episodes
    }

    // ------------------------------------------------------------------
    // Stream extraction
    // ------------------------------------------------------------------

    override suspend fun loadLinks(
        data: String,
        isCasting: Boolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        val parts = data.split("|")
        val subjectId = extractSubjectId(parts[0])
        val season = parts.getOrNull(1)?.toIntOrNull() ?: 0
        val episode = parts.getOrNull(2)?.toIntOrNull() ?: 0

        // 1. Detail request also hands us the guest JWT in the x-user header
        val detailUrl = "$mainUrl/wefeed-mobile-bff/subject-api/get?subjectId=$subjectId"
        val detailResponse = try {
            app.get(detailUrl, headers = authHeaders(detailUrl))
        } catch (_: Exception) {
            return false
        }

        val jwt = detailResponse.headers["x-user"]
            ?.let { runCatching { jacksonObjectMapper().readTree(it)["token"]?.asText() }.getOrNull() }

        // 2. Build (subjectId, language label) pairs — original plus dubs
        val variants = mutableListOf(subjectId to "Original")
        runCatching {
            val root = jacksonObjectMapper().readTree(detailResponse.text)
            root["data"]?.get("dubs")?.forEach { dub ->
                val sid = dub["subjectId"]?.asText() ?: return@forEach
                val label = dub["lanName"]?.asText()?.replace("dub", "Audio") ?: "Dub"
                if (sid != subjectId) variants.add(sid to label)
            }
        }

        var emitted = false

        for ((sid, language) in variants.distinctBy { it.first }) {
            val playUrl = "$mainUrl/wefeed-mobile-bff/subject-api/play-info" +
                    "?subjectId=$sid&se=$season&ep=$episode"

            val playResponse = try {
                app.get(playUrl, headers = authHeaders(playUrl, token = jwt))
            } catch (_: Exception) {
                continue
            }
            if (playResponse.code != 200) continue

            val mapper = jacksonObjectMapper()
            val streams = try {
                mapper.readTree(playResponse.text)["data"]?.get("streams")
            } catch (_: Exception) {
                null
            }

            if (streams != null && streams.isArray && streams.size() > 0) {
                for (stream in streams) {
                    if (emitStream(stream, subjectId, season, episode, language, jwt, callback, subtitleCallback)) {
                        emitted = true
                    }
                }
            } else {
                // Some older series entries expose links under resourceDetectors
                if (emitFallbackStreams(sid, language, mapper, callback)) {
                    emitted = true
                }
            }
        }

        return emitted
    }

    private suspend fun emitStream(
        stream: JsonNode,
        subjectId: String,
        season: Int,
        episode: Int,
        language: String,
        jwt: String?,
        callback: (ExtractorLink) -> Unit,
        subtitleCallback: (SubtitleFile) -> Unit
    ): Boolean {
        val streamUrl = stream["url"]?.asText()?.takeIf { it.isNotBlank() } ?: return false
        val format = stream["format"]?.asText() ?: ""
        val resolutions = stream["resolutions"]?.asText() ?: ""
        val signCookie = stream["signCookie"]?.asText()?.takeIf { it.isNotBlank() }
        val streamId = stream["id"]?.asText() ?: "$subjectId|$season|$episode"

        // Skip MovieBox's decoy sample stream
        if (streamUrl.contains("b164fbfb4347792950bdfbfb563d39d9", ignoreCase = true)) return false
        val duration = stream["duration"]?.asLong(0L) ?: 0L
        if (duration in 1..299) return false

        val quality = mapResolutionToQuality(resolutions)

        callback.invoke(
            newExtractorLink(
                source = "$name ($language)",
                name = "$name ($language)",
                url = streamUrl,
                type = detectLinkType(streamUrl, format)
            ) {
                this.referer = mainUrl
                this.quality = quality ?: Qualities.Unknown.value
                val extraHeaders = mutableMapOf("Referer" to mainUrl)
                if (signCookie != null) extraHeaders["Cookie"] = signCookie
                this.headers = extraHeaders
            }
        )

        // Subtitles from both caption endpoints
        collectSubtitles(subjectId, streamId, language, jwt, subtitleCallback)
        collectExternalSubtitles(subjectId, streamId, language, jwt, subtitleCallback)

        return true
    }

    private fun detectLinkType(url: String, format: String): ExtractorLinkType = when {
        url.startsWith("magnet:", ignoreCase = true) -> ExtractorLinkType.MAGNET
        url.contains(".mpd", ignoreCase = true) -> ExtractorLinkType.DASH
        url.substringAfterLast('.', "").equals("torrent", ignoreCase = true) -> ExtractorLinkType.TORRENT
        format.equals("HLS", ignoreCase = true) -> ExtractorLinkType.M3U8
        url.substringAfterLast('.', "").equals("m3u8", ignoreCase = true) -> ExtractorLinkType.M3U8
        url.contains(".mp4", ignoreCase = true) || url.contains(".mkv", ignoreCase = true) ->
            ExtractorLinkType.VIDEO
        else -> ExtractorLinkType.M3U8
    }

    private fun mapResolutionToQuality(resolutions: String): Int? {
        val table = listOf(
            "2160" to Qualities.P2160.value,
            "1440" to Qualities.P1440.value,
            "1080" to Qualities.P1080.value,
            "720" to Qualities.P720.value,
            "480" to Qualities.P480.value,
            "360" to Qualities.P360.value,
            "240" to Qualities.P240.value
        )
        return table.firstOrNull { resolutions.contains(it.first, ignoreCase = true) }?.second
    }

    private suspend fun collectSubtitles(
        subjectId: String,
        streamId: String,
        language: String,
        jwt: String?,
        callback: (SubtitleFile) -> Unit
    ) {
        val url = "$mainUrl/wefeed-mobile-bff/subject-api/get-stream-captions" +
                "?subjectId=$subjectId&streamId=$streamId"
        val response = try {
            app.get(url, headers = authHeaders(url, token = jwt))
        } catch (_: Exception) {
            return
        }
        val captions = try {
            jacksonObjectMapper().readTree(response.text)["data"]?.get("extCaptions")
        } catch (_: Exception) {
            null
        } ?: return

        for (caption in captions) {
            val link = caption["url"]?.asText()?.takeIf { it.isNotBlank() } ?: continue
            val label = caption["language"]?.asText()
                ?: caption["lanName"]?.asText()
                ?: caption["lan"]?.asText()
                ?: "Unknown"
            callback.invoke(newSubtitleFile(link, "$label ($language)"))
        }
    }

    private suspend fun collectExternalSubtitles(
        subjectId: String,
        streamId: String,
        language: String,
        jwt: String?,
        callback: (SubtitleFile) -> Unit
    ) {
        val url = "$mainUrl/wefeed-mobile-bff/subject-api/get-ext-captions" +
                "?subjectId=$subjectId&resourceId=$streamId&episode=0"
        val response = try {
            app.get(url, headers = authHeaders(url, token = jwt))
        } catch (_: Exception) {
            return
        }
        val captions = try {
            jacksonObjectMapper().readTree(response.text)["data"]?.get("extCaptions")
        } catch (_: Exception) {
            null
        } ?: return

        for (caption in captions) {
            val link = caption["url"]?.asText()?.takeIf { it.isNotBlank() } ?: continue
            val label = caption["lan"]?.asText()
                ?: caption["lanName"]?.asText()
                ?: caption["language"]?.asText()
                ?: "Unknown"
            callback.invoke(newSubtitleFile(link, "$label ($language)"))
        }
    }

    private suspend fun emitFallbackStreams(
        subjectId: String,
        language: String,
        mapper: com.fasterxml.jackson.databind.ObjectMapper,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        val url = "$mainUrl/wefeed-mobile-bff/subject-api/get?subjectId=$subjectId"
        val response = try {
            app.get(url, headers = authHeaders(url))
        } catch (_: Exception) {
            return false
        }
        if (response.code != 200) return false

        val detectors = try {
            mapper.readTree(response.text)["data"]?.get("resourceDetectors")
        } catch (_: Exception) {
            null
        } ?: return false

        var emitted = false
        for (detector in detectors) {
            val resolutions = detector["resolutionList"] ?: continue
            for (video in resolutions) {
                val link = video["resourceLink"]?.asText()?.takeIf { it.isNotBlank() } ?: continue
                val quality = video["resolution"]?.asInt() ?: 0
                val se = video["se"]?.asInt()
                val ep = video["ep"]?.asInt()

                callback.invoke(
                    newExtractorLink(
                        source = "$name ($language)",
                        name = "$name S${se}E${ep} ${quality}p ($language)",
                        url = link,
                        type = ExtractorLinkType.VIDEO
                    ) {
                        this.referer = mainUrl
                        this.quality = quality
                        this.headers = mapOf("Referer" to mainUrl)
                    }
                )
                emitted = true
            }
        }
        return emitted
    }

    // ------------------------------------------------------------------
    // TMDB + Cinemeta enrichment (optional but improves metadata quality)
    // ------------------------------------------------------------------

    private val tmdbKey = "1865f43a0549ca50d341dd9ab8b29f49"

    private suspend fun identifyOnTmdb(
        title: String,
        year: Int?,
        rating: Double?
    ): Pair<Int?, String?> {
        val cleaned = normalizeTitle(title)
        val queries = listOf(
            "search/multi" to "&query=$cleaned" + (year?.let { "&year=$it" } ?: ""),
            "search/tv" to "&query=$cleaned" + (year?.let { "&first_air_date_year=$it" } ?: ""),
            "search/movie" to "&query=$cleaned" + (year?.let { "&year=$it" } ?: "")
        )

        var bestId: Int? = null
        var bestScore = 0.0
        var bestIsTv = false

        for ((endpoint, suffix) in queries) {
            val url = "https://api.themoviedb.org/3/$endpoint?api_key=$tmdbKey" +
                    "$suffix&include_adult=false&page=1"
            val results = try {
                JSONObject(app.get(url).text).optJSONArray("results")
            } catch (_: Exception) {
                null
            } ?: continue

            for (i in 0 until results.length()) {
                val obj = results.getJSONObject(i)
                val mediaType = when (endpoint) {
                    "search/tv" -> "tv"
                    "search/movie" -> "movie"
                    else -> obj.optString("media_type", "")
                }
                val candidateId = obj.optInt("id", -1)
                if (candidateId == -1) continue

                val titles = listOf(
                    obj.optString("title"),
                    obj.optString("name"),
                    obj.optString("original_title"),
                    obj.optString("original_name")
                ).filter { it.isNotBlank() }

                val date = if (mediaType == "tv") {
                    obj.optString("first_air_date", "")
                } else {
                    obj.optString("release_date", "")
                }
                val candidateYear = date.take(4).toIntOrNull()
                val candidateRating = obj.optDouble("vote_average", Double.NaN)

                var score = 0.0
                if (titles.any { tokenMatch(normalizeTitle(it), cleaned) }) score += 50.0
                else if (titles.any { it.contains(cleaned, true) || cleaned.contains(normalizeTitle(it), true) }) {
                    score += 20.0
                }
                if (year != null && candidateYear == year) score += 35.0
                if (rating != null && !candidateRating.isNaN()) {
                    val delta = kotlin.math.abs(candidateRating - rating)
                    score += when {
                        delta <= 0.5 -> 10.0
                        delta <= 1.0 -> 5.0
                        else -> 0.0
                    }
                }
                score += (obj.optDouble("popularity", 0.0) / 100.0).coerceAtMost(5.0)

                if (score > bestScore) {
                    bestScore = score
                    bestId = candidateId
                    bestIsTv = mediaType == "tv"
                }
            }
        }

        if (bestId == null || bestScore < 40.0) return null to null

        val kind = if (bestIsTv) "tv" else "movie"
        val detailUrl = "https://api.themoviedb.org/3/$kind/$bestId" +
                "?api_key=$tmdbKey&append_to_response=external_ids"
        val imdbId = try {
            JSONObject(app.get(detailUrl).text)
                .optJSONObject("external_ids")?.optString("imdb_id")
        } catch (_: Exception) {
            null
        }
        return bestId to imdbId
    }

    private fun normalizeTitle(raw: String): String = raw
        .replace("\\[.*?]".toRegex(), " ")
        .replace("\\(.*?\\)".toRegex(), " ")
        .replace("(?i)\\b(dub|dubbed|hd|4k|hindi|tamil|telugu|dual audio)\\b".toRegex(), " ")
        .replace("\\p{Punct}".toRegex(), " ")
        .replace("\\s+".toRegex(), " ")
        .trim()
        .lowercase()

    private fun tokenMatch(a: String, b: String): Boolean {
        val sa = a.split("\\s+".toRegex()).filter { it.isNotBlank() }.toSet()
        val sb = b.split("\\s+".toRegex()).filter { it.isNotBlank() }.toSet()
        if (sa.isEmpty() || sb.isEmpty()) return false
        val overlap = sa.intersect(sb).size
        return overlap >= maxOf(1, minOf(sa.size, sb.size) * 3 / 4)
    }

    private suspend fun fetchCinemeta(imdbId: String, type: TvType): JsonNode? {
        val kind = if (type == TvType.TvSeries) "series" else "movie"
        val url = "https://v3-cinemeta.strem.io/meta/$kind/$imdbId.json"
        return try {
            mapper.readTree(app.get(url).text)["meta"]
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun fetchTmdbLogo(tmdbId: Int?, type: TvType): String? {
        if (tmdbId == null) return null
        val kind = if (type == TvType.Movie) "movie" else "tv"
        val url = "https://api.themoviedb.org/3/$kind/$tmdbId/images?api_key=$tmdbKey"

        val logos = try {
            JSONObject(app.get(url).text).optJSONArray("logos")
        } catch (_: Exception) {
            null
        } ?: return null
        if (logos.length() == 0) return null

        fun path(obj: JSONObject): String = obj.optString("file_path")
        fun isSvg(obj: JSONObject): Boolean = path(obj).endsWith(".svg", true)
        fun publicUrl(obj: JSONObject): String = "https://image.tmdb.org/t/p/w500${path(obj)}"

        var best: JSONObject? = null
        var bestSvg: JSONObject? = null

        for (i in 0 until logos.length()) {
            val logo = logos.optJSONObject(i) ?: continue
            if (path(logo).isBlank()) continue
            if (logo.optDouble("vote_average", 0.0) <= 0 || logo.optInt("vote_count", 0) <= 0) continue

            if (isSvg(logo)) {
                if (bestSvg == null || logo.optDouble("vote_average") > bestSvg.optDouble("vote_average")) {
                    bestSvg = logo
                }
            } else {
                if (best == null || logo.optDouble("vote_average") > best.optDouble("vote_average")) {
                    best = logo
                }
            }
        }

        return best?.let(::publicUrl) ?: bestSvg?.let(::publicUrl)
    }
}