package dev.slt.android.ui

import android.content.ClipDescription
import org.junit.Assert.assertEquals
import org.junit.Test

class UiMessagesTest {
    @Test
    fun sensitiveClipboardTextMarksLogPayloadSensitive() {
        val clipboardText = sensitiveClipboardText(
            label = "SLT log",
            text = "token=redacted",
        )

        assertEquals("SLT log", clipboardText.label)
        assertEquals("token=redacted", clipboardText.text)
        assertEquals(
            mapOf(ClipDescription.EXTRA_IS_SENSITIVE to true),
            clipboardText.booleanExtras,
        )
    }
}
