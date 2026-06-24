package dev.slt.android.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

/**
 * SLT brand color system — the "Soft Circuit" (C2) palette.
 *
 * Dark is the primary design target: a confident green (`#36C172`) on near-black,
 * faintly green-tinted surfaces. [LightColorScheme] is the tonal inverse of the
 * same Material 3 roles. Screens read only
 * [androidx.compose.material3.MaterialTheme.colorScheme], so they never branch on
 * theme — maintaining both schemes is just keeping these two tables consistent.
 */

// Status semantics (consumed by the status pill). "Connected" reuses the scheme
// `primary`; "error" reuses `error`; "connecting" is a standalone amber.
/** Status color for the connecting / reconnecting state, dark scheme. */
val StatusConnectingDark = Color(0xFFE0A33D)

/** Status color for the connecting / reconnecting state, light scheme. */
val StatusConnectingLight = Color(0xFF8A6A26)

internal val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF36C172),
    onPrimary = Color(0xFF02230F),
    primaryContainer = Color(0xFF0E3820),
    onPrimaryContainer = Color(0xFF9FE6B6),
    inversePrimary = Color(0xFF1E7A43),
    secondary = Color(0xFF94A89B),
    onSecondary = Color(0xFF0F1A13),
    secondaryContainer = Color(0xFF222B26),
    onSecondaryContainer = Color(0xFFB0C6B5),
    tertiary = Color(0xFF57B0A8),
    onTertiary = Color(0xFF002B27),
    tertiaryContainer = Color(0xFF1C3A36),
    onTertiaryContainer = Color(0xFF9EE8DE),
    background = Color(0xFF080A09),
    onBackground = Color(0xFFEDF2EE),
    surface = Color(0xFF0F1311),
    onSurface = Color(0xFFEDF2EE),
    surfaceVariant = Color(0xFF1A211C),
    onSurfaceVariant = Color(0xFF869289),
    surfaceTint = Color(0xFF36C172),
    inverseSurface = Color(0xFFEDF2EE),
    inverseOnSurface = Color(0xFF141916),
    error = Color(0xFFE5484D),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    outline = Color(0xFF414C45),
    outlineVariant = Color(0xFF283129),
    scrim = Color(0xFF000000),
    surfaceDim = Color(0xFF0A0D0B),
    surfaceBright = Color(0xFF1A201D),
    surfaceContainerLowest = Color(0xFF050706),
    surfaceContainerLow = Color(0xFF0E1310),
    surfaceContainer = Color(0xFF121815),
    surfaceContainerHigh = Color(0xFF181E1A),
    surfaceContainerHighest = Color(0xFF1E2520),
)

internal val LightColorScheme = lightColorScheme(
    primary = Color(0xFF1E7A43),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFB4F0C8),
    onPrimaryContainer = Color(0xFF00210E),
    inversePrimary = Color(0xFF36C172),
    secondary = Color(0xFF506352),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFD3E8D3),
    onSecondaryContainer = Color(0xFF0E1F11),
    tertiary = Color(0xFF3A6373),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFBFEAF8),
    onTertiaryContainer = Color(0xFF001E2A),
    background = Color(0xFFF6FBF7),
    onBackground = Color(0xFF161D18),
    surface = Color(0xFFF6FBF7),
    onSurface = Color(0xFF161D18),
    surfaceVariant = Color(0xFFDCE5DE),
    onSurfaceVariant = Color(0xFF414942),
    surfaceTint = Color(0xFF1E7A43),
    inverseSurface = Color(0xFF161D18),
    inverseOnSurface = Color(0xFFEDF2EE),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    outline = Color(0xFF717871),
    outlineVariant = Color(0xFFC0C9C2),
    scrim = Color(0xFF000000),
    surfaceDim = Color(0xFFD6DBD6),
    surfaceBright = Color(0xFFFBFFFB),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF0F5F0),
    surfaceContainer = Color(0xFFEAEFEA),
    surfaceContainerHigh = Color(0xFFE4EAE4),
    surfaceContainerHighest = Color(0xFFDEE4DE),
)
