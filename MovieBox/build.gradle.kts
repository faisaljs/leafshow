version = 1

android {
    namespace = "com.leafshow.moviebox"
    buildFeatures {
        buildConfig = true
    }
}

cloudstream {
    language = "hi"
    description = "MovieBox — multilingual movies and series"
    authors = listOf("faisaljs")
    status = 1
    tvTypes = listOf("Movie", "TvSeries")
    iconUrl = "https://moviebox.ph/favicon.ico"
    isCrossPlatform = false
}