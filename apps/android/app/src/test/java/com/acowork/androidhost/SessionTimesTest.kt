package com.acowork.androidhost

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The only rule on the agent detail page that can be wrong without a device:
 * where one age bucket ends and the next begins.
 */
class SessionTimesTest {
    private val now = 1_700_000_000_000L

    private fun ago(ms: Long): SessionAge = SessionTimes.ageOf(now, now - ms)

    @Test
    fun `sub-minute reads as just now`() {
        assertEquals(SessionAge.JustNow, ago(0))
        assertEquals(SessionAge.JustNow, ago(59_999))
    }

    @Test
    fun `minutes bucket starts at exactly one minute`() {
        assertEquals(SessionAge.Minutes(1), ago(60_000))
        assertEquals(SessionAge.Minutes(59), ago(59 * 60_000L + 59_999))
    }

    @Test
    fun `hours bucket starts at exactly one hour`() {
        assertEquals(SessionAge.Hours(1), ago(60 * 60_000L))
        assertEquals(SessionAge.Hours(23), ago(24 * 60 * 60_000L - 1))
    }

    @Test
    fun `days bucket starts at exactly one day`() {
        assertEquals(SessionAge.Days(1), ago(24 * 60 * 60_000L))
        assertEquals(SessionAge.Days(29), ago(30 * 24 * 60 * 60_000L - 1))
    }

    @Test
    fun `thirty days and older falls back to a date`() {
        val atMs = now - 30 * 24 * 60 * 60_000L
        assertEquals(SessionAge.On(atMs), SessionTimes.ageOf(now, atMs))
    }

    /** A clock that ran ahead must not produce a negative duration. */
    @Test
    fun `future timestamp reads as just now`() {
        assertEquals(SessionAge.JustNow, SessionTimes.ageOf(now, now + 5 * 60_000L))
    }

    @Test
    fun `buckets are ordered as time passes`() {
        val samples = listOf(
            ago(0),
            ago(90_000),
            ago(2 * 60 * 60_000L),
            ago(3 * 24 * 60 * 60_000L),
            ago(90 * 24 * 60 * 60_000L),
        )
        assertTrue(samples[0] is SessionAge.JustNow)
        assertEquals(SessionAge.Minutes(1), samples[1])
        assertEquals(SessionAge.Hours(2), samples[2])
        assertEquals(SessionAge.Days(3), samples[3])
        assertTrue(samples[4] is SessionAge.On)
    }
}