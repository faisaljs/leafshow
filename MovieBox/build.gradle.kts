version = 1

cloudstream {
    description = "MovieBox — movies and TV series"
    authors = listOf("leafshow")
    status = 1
    tvTypes = listOf("Movie", "TvSeries")
    language = "en"
    iconUrl = "https://moviebox.ph/favicon.ico"
}

android {
    namespace = "com.leafshow.moviebox"   // overrides root's com.example

    buildFeatures {
        buildConfig = true
    }
}