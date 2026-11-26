// ignore: deprecated_member_use
import 'package:flutter/material.dart';

/// Design tokens (silentsnake.yaml design.style): dark theme, glassy gradient cards, soft
/// glow accents. Risk colours follow design.color_and_accessibility.risk_scale and are
/// always paired with a label and an icon, never colour alone.
abstract final class Palette {
  static const bg = Color(0xFF060A13);
  static const cardTop = Color(0xFF111A2E);
  static const cardBottom = Color(0xFF0A1120);
  static const border = Color(0x1AFFFFFF);
  static const text = Color(0xFFE6EDF7);
  static const muted = Color(0xFF8C9AB3);
  static const faint = Color(0xFF55627A);
  static const accent = Color(0xFF4F8CFF);
  static const accentGlow = Color(0xFF7FB0FF);
  static const violet = Color(0xFF9B7BFF);
  static const ember = Color(0xFFE0703A);

  static const green = Color(0xFF3DDC97);
  static const yellow = Color(0xFFF5C84B);
  static const orange = Color(0xFFFF9A4D);
  static const red = Color(0xFFFF6B6B);
}

class RiskStyle {
  const RiskStyle(this.label, this.color, this.icon);
  final String label;
  final Color color;
  final IconData icon;

  static RiskStyle of(String level) => switch (level) {
    'high' => const RiskStyle('High', Palette.red, Icons.gpp_bad_outlined),
    'elevated' => const RiskStyle('Elevated', Palette.orange, Icons.warning_amber_rounded),
    'guarded' => const RiskStyle('Guarded', Palette.yellow, Icons.shield_outlined),
    _ => const RiskStyle('Low', Palette.green, Icons.verified_user_outlined),
  };

  static RiskStyle forScore(int score) => of(
    score >= 75
        ? 'high'
        : score >= 50
        ? 'elevated'
        : score >= 25
        ? 'guarded'
        : 'low',
  );
}

/// Direction is encoded by shape (arrow icon), not colour, so it never clashes with risk.
IconData directionIcon(String d) => switch (d) {
  'outbound' => Icons.north_east_rounded,
  'inbound' => Icons.south_west_rounded,
  'local' => Icons.sync_alt_rounded,
  'transit' => Icons.swap_calls_rounded,
  _ => Icons.help_outline_rounded,
};

ThemeData buildTheme() {
  const font = 'DejaVu Sans';
  final base = ThemeData(brightness: Brightness.dark, fontFamily: font, useMaterial3: true);
  return base.copyWith(
    scaffoldBackgroundColor: Palette.bg,
    colorScheme: base.colorScheme.copyWith(primary: Palette.accent, surface: Palette.cardBottom),
    textTheme: base.textTheme.apply(bodyColor: Palette.text, displayColor: Palette.text),
    tooltipTheme: const TooltipThemeData(
      decoration: BoxDecoration(color: Color(0xFF1B2640), borderRadius: BorderRadius.all(Radius.circular(8))),
      textStyle: TextStyle(color: Palette.text, fontSize: 12),
    ),
  );
}
