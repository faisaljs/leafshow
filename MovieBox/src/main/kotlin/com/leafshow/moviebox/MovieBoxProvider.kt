package com.leafshow.moviebox

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.lagradost.cloudstream3.*
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.ExtractorLinkType
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.newExtractorLink
import java.net.URLEncoder

class MovieBoxProvider : MainAPI() {
    override var mainUrl = "https://moviebox.ph"
    override var name = "MovieBox"
    override val supportedTypes = setOf(TvType.Movie, TvType.TvSeries)
    override var lang = "en"
    override val hasMainPage = true

    override val mainPage = mainPageOf(
        "home" to "Home"
    )

    private val apiBase = "https://h5-api.aoneroom.com/wefeed-h5api-bff"
    private val siteHost = "moviebox.ph"
    private val mapper = ObjectMapper()

    @Volatile
    private var bearer: String? = null

    private val baseHeaders: Map<String, String>
        get() = mapOf(
            "User-Agent" to "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 " +
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Accept" to "application/json",
            "Referer" to "https://$siteHost/",
            "Origin" to "https://$siteHost",
            "X-Client-Info" to "{\"timezone\":\"UTC\"}",
            "X-Request-Lang" to "en"
        )

    // ------------------------------------------------------------------
    // API plumbing
    // ------------------------------------------------------------------

    private fun encodeUrl(value: String): String =
        try {
            URLEncoder.encode(value, "UTF-8").replace("+", "%20")
        } catch (e: Exception) {
            value
        }

    private fun apiUrl(path: String, params: Map<String, String>): String {
        val all = linkedMapOf("host" to siteHost).apply { putAll(params) }
        val query = all.entries.joinToString("&") {
            "${it.key}=${encodeUrl(it.value)}"
        }
        return "$apiBase$path?$query"
    }

    private suspend fun authHeader(): String? {
        bearer?.let { return "Bearer $it" }

        val response = app.get("$apiBase/home?host=$siteHost", headers = baseHeaders)
        val raw = response.headers["x-user"] ?: return null
        val token = Regex("\"token\"\\s*:\\s*\"([^\"]+)\"")
            .find(raw)?.groupValues?.getOrNull(1)
            ?: return null

        bearer = token
        return "Bearer $token"
    }

    private suspend fun api(
        path: String,
        params: Map<String, String> = emptyMap()
    ): JsonNode? {
        val auth = authHeader()
        val headers = if (auth != null) {
            baseHeaders + ("Authorization" to auth)
        } else {
            baseHeaders
        }

        return runCatching {
            mapper.readTree(app.get(apiUrl(path, params), headers = headers).text)
        }.getOrNull()
    }

    // ------------------------------------------------------------------
    // Home
    // ------------------------------------------------------------------

    override suspend fun getMainPage(page: Int, request: MainPageRequest): HomePageResponse {
        val root = api(
            "/home",
            mapOf("page" to page.toString(), "perPage" to "30")
        ) ?: return newHomePageResponse(request.name, emptyList())

        val found = LinkedHashMap<String, SearchResponse>()
        collectSubjects(root.path("data"), found)

        return newHomePageResponse(request.name, found.values.toList())
    }

    // ------------------------------------------------------------------
    // Search
    // ------------------------------------------------------------------

    override suspend fun search(query: String): List<SearchResponse> {
        val root = api(
            "/subject/everyone-search",
            mapOf("keyword" to query, "page" to "1", "perPage" to "24")
        ) ?: return emptyList()

        val found = LinkedHashMap<String, SearchResponse>()
        collectSubjects(root.path("data"), found)

        return found.values.toList()
    }

    private fun collectSubjects(node: JsonNode?, out: MutableMap<String, SearchResponse>) {
        if (node == null || node.isNull) return

        if (node.isArray) {
            node.forEach { collectSubjects(it, out) }
            return
        }
        if (!node.isObject) return

        val id = node.path("subjectId").asText("")
        val title = node.path("title").asText("")

        if (id.isNotBlank() && title.isNotBlank()) {
            out[id] = node.toSearchResponse()
        } else {
            node.elements().forEach { collectSubjects(it, out) }
        }
    }

    private fun JsonNode.toSearchResponse(): SearchResponse {
        val id = path("subjectId").asText()
        val title = path("title").asText()
        val detailPath = path("detailPath").asText("")

        val poster = path("cover").path("url").asText(null)
            ?: path("poster").path("url").asText(null)
            ?: path("coverUrl").asText(null)

        val type = when {
            path("subjectType").asInt(1) == 2 -> TvType.TvSeries
            path("seasons").isArray -> TvType.TvSeries
            path("episodeCount").asInt(0) > 0 -> TvType.TvSeries
            else -> TvType.Movie
        }

        return newMovieSearchResponse(title, "$id|$detailPath", type) {
            this.posterUrl = poster
        }
    }

    // ------------------------------------------------------------------
    // Detail
    // ------------------------------------------------------------------

    private suspend fun fetchDetail(subjectId: String, detailPath: String): JsonNode? {
        val attempts = listOf(
            "/subject/get-subject-detail" to mapOf(
                "subjectId" to subjectId,
                "detailPath" to detailPath
            ),
            "/detail" to mapOf(
                "subjectId" to subjectId,
                "detailPath" to detailPath
            ),
            "/subject/detail" to mapOf(
                "subjectId" to subjectId,
                "detailPath" to detailPath
            )
        )

        for ((path, params) in attempts) {
            val root = api(path, params) ?: continue
            val data = root.path("data")
            if (data.path("subject").isObject || data.path("title").asText("").isNotBlank()) {
                return data
            }
        }
        return null
    }

    override suspend fun load(url: String): LoadResponse? {
        val parts = url.split('|')
        val subjectId = parts.getOrNull(0).orEmpty()
        val detailPath = parts.getOrNull(1).orEmpty()

        if (subjectId.isBlank()) return null

        val data = fetchDetail(subjectId, detailPath) ?: return null
        val subject = data.path("subject").takeIf { it.isObject } ?: data

        val title = subject.path("title").asText("Untitled")
        val poster = subject.path("cover").path("url").asText(null)
            ?: subject.path("poster").path("url").asText(null)
        val plot = subject.path("description").asText(null)
            ?: subject.path("synopsis").asText(null)
        val year = subject.path("releaseDate").asText("").take(4).toIntOrNull()
        val durationMinutes = (subject.path("duration").asInt(0) / 60).takeIf { it > 0 }

        val seasons = data.path("seasons").takeIf { it.isArray }
            ?: subject.path("seasons").takeIf { it.isArray }
            ?: data.path("resource").path("seasons").takeIf { it.isArray }

        val episodes = mutableListOf<Episode>()

        if (seasons != null) {
            seasons.forEachIndexed { seasonIndex, season ->
                val seasonNumber = season.path("se").asInt(seasonIndex + 1)
                val episodeArray = season.path("episodes")
                if (!episodeArray.isArray) return@forEachIndexed

                episodeArray.forEachIndexed { episodeIndex, episode ->
                    val episodeNumber = episode.path("ep").asInt(episodeIndex + 1)
                    val episodeId = episode.path("episodeId").asText("")
                        .ifBlank { episode.path("id").asText("") }

                    episodes.add(
                        newEpisode(
                            "$subjectId|$detailPath|$seasonNumber|$episodeNumber|$episodeId"
                        ) {
                            this.name = episode.path("title").asText("Episode $episodeNumber")
                            this.season = seasonNumber
                            this.episode = episodeNumber
                            this.posterUrl =
                                episode.path("cover").path("url").asText(null) ?: poster
                        }
                    )
                }
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
                this.duration = durationMinutes
            }
        }
    }

    // ------------------------------------------------------------------
    // Links
    // ------------------------------------------------------------------

    private suspend fun fetchPlay(
        subjectId: String,
        detailPath: String,
        season: Int?,
        episode: Int?,
        episodeId: String?
    ): JsonNode? {
        val base = linkedMapOf(
            "subjectId" to subjectId,
            "detailPath" to detailPath,
            "resolution" to "720",
            "page" to "1"
        )
        if (season != null) base["se"] = season.toString()
        if (episode != null) base["ep"] = episode.toString()
        if (!episodeId.isNullOrBlank()) base["episodeId"] = episodeId

        val attempts = listOf("/subject/play", "/play", "/subject/get-play-info")
        for (path in attempts) {
            val root = api(path, base) ?: continue
            val data = root.path("data")
            if (data.path("streams").isArray ||
                data.path("playInfo").isArray ||
                data.path("videoUrl").asText("").isNotBlank()
            ) {
                return data
            }
        }
        return null
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

        val playData = fetchPlay(subjectId, detailPath, season, episode, episodeId)
            ?: return false

        val streamNodes: MutableList<JsonNode> = mutableListOf()

        playData.path("streams").takeIf { it.isArray }?.forEach { node ->
            streamNodes.add(node)
        }
        playData.path("playInfo").takeIf { it.isArray }?.forEach { node ->
            streamNodes.add(node)
        }
        playData.path("videos").takeIf { it.isArray }?.forEach { node ->
            streamNodes.add(node)
        }

        if (streamNodes.isEmpty() && playData.isObject) {
            val directUrl = playData.path("videoUrl").asText("")
                .ifBlank { playData.path("playUrl").asText("") }
            if (directUrl.isNotBlank()) streamNodes.add(playData)
        }

        var emitted = false

        for (stream in streamNodes) {
            val streamUrl = stream.path("url").asText("")
                .ifBlank { stream.path("playUrl").asText("") }
                .ifBlank { stream.path("streamUrl").asText("") }
                .ifBlank { stream.path("videoUrl").asText("") }

            if (streamUrl.isBlank()) continue

            val resolution = stream.path("resolution").asInt(0)
                .takeIf { it > 0 }
                ?: stream.path("quality").asInt(0)
                ?: stream.path("height").asInt(0)

            val quality = when {
                resolution >= 1080 -> Qualities.P1080.value
                resolution >= 720 -> Qualities.P720.value
                resolution >= 480 -> Qualities.P480.value
                resolution >= 360 -> Qualities.P360.value
                else -> Qualities.Unknown.value
            }

            callback.invoke(
                newExtractorLink(
                    source = name,
                    name = if (resolution > 0) "$name ${resolution}p" else name,
                    url = streamUrl,
                    type = if (streamUrl.contains(".m3u8", ignoreCase = true)) {
                        ExtractorLinkType.M3U8
                    } else {
                        ExtractorLinkType.MP4
                    }
                ) {
                    this.referer = mainUrl
                    this.quality = quality
                    this.headers = mapOf(
                        "User-Agent" to "ExoPlayerLib/2.19.1",
                        "Accept" to "*/*",
                        "Referer" to "https://$siteHost/",
                        "Origin" to "https://$siteHost"
                    )
                }
            )
            emitted = true
        }

        val subtitles = playData.path("subtitles").takeIf { it.isArray }
            ?: playData.path("captions").takeIf { it.isArray }

        subtitles?.forEach { subtitle ->
            val url = subtitle.path("url").asText("")
            if (url.isBlank()) return@forEach

            val language = subtitle.path("language").asText("")
                .ifBlank { subtitle.path("lang").asText("") }
                .ifBlank { subtitle.path("name").asText("Unknown") }

            subtitleCallback.invoke(SubtitleFile(language, url))
        }

        return emitted
    }
}