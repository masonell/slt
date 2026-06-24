package dev.slt.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

/**
 * SLT app theme.
 *
 * Picks the brand color scheme from the system dark/light setting, applies the
 * SLT typography and shape scales, and forces the brand palette (no Material You
 * dynamic color, so the green identity is stable). Wrap the app once near the
 * root; screens read [MaterialTheme.colorScheme] / [MaterialTheme.typography].
 *
 * @param darkTheme whether to use the dark scheme; defaults to the system setting.
 */
@Composable
fun SltTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = SltTypography,
        shapes = SltShapes,
        content = content,
    )
}
