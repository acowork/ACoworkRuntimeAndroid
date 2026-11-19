package com.acowork.androidhost

/**
 * How old a session timestamp is, as a value rather than as a sentence.
 *
 * The bucketing is pure integer arithmetic on purpose: it is the only part of
 * the detail page with a rule worth testing (boundaries, clock skew, the
 * 30-day hand-off to a calendar date), and keeping the strings out of it means
 * a JVM unit test can cover it without an emulator.
 *
 * The thresholds mirror the desktop panel's `formatRelativeTime`, so the same
 * session reads the same age on both surfaces.
 */
sealed interface SessionAge {
    data object JustNow : SessionAge
    data class Minutes(val count: Long) : SessionAge
    data class Hours(val count: Long) : SessionAge
    data class Days(val count: Long) : SessionAge

    /** Older than [SessionTimes.LONG_AGO_DAYS]: show a date instead of a duration. */
    data class On(val atMs: Long) : SessionAge
}

object SessionTimes {
    const val LONG_AGO_DAYS = 30L

    private const val MINUTE_MS = 60_000L
    private const val HOUR_MS = 60 * MINUTE_MS
    private const val DAY_MS = 24 * HOUR_MS

    /**
     * Classify [atMs] relative to [nowMs].
     *
     * A timestamp in the future (device clock moved, or a store written by a
     * node whose clock ran ahead) reads as [SessionAge.JustNow] instead of a
     * negative duration — "in -3 min" is not a thing an operator can act on.
     */
    fun ageOf(nowMs: Long, atMs: Long): SessionAge {
        val elapsed = nowMs - atMs
        if (elapsed < MINUTE_MS) return SessionAge.JustNow
        if (elapsed < HOUR_MS) return SessionAge.Minutes(elapsed / MINUTE_MS)
        if (elapsed < DAY_MS) return SessionAge.Hours(elapsed / HOUR_MS)
        val days = elapsed / DAY_MS
        if (days < LONG_AGO_DAYS) return SessionAge.Days(days)
        return SessionAge.On(atMs)
    }
}