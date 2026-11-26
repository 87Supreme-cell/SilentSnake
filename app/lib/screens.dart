// ignore: deprecated_member_use
import 'package:flutter/material.dart';

import 'controller.dart';
import 'dashboard.dart';
import 'models.dart';
import 'theme.dart';
import 'widgets.dart';

/// All connections, filterable to flagged ones.
class ConnectionsScreen extends StatefulWidget {
  const ConnectionsScreen({super.key, required this.c});
  final DashboardController c;
  @override
  State<ConnectionsScreen> createState() => _ConnectionsScreenState();
}

class _ConnectionsScreenState extends State<ConnectionsScreen> {
  bool flaggedOnly = false;
  @override
  Widget build(BuildContext context) {
    final all = widget.c.connections;
    final list = flaggedOnly ? all.where((x) => x.flagged).toList() : all;
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 4, 24, 24),
      child: GlassCard(
        title: 'Connections',
        trailing: FilterChip(
          label: const Text('Flagged only'),
          selected: flaggedOnly,
          avatar: const Icon(Icons.flag_rounded, size: 16),
          onSelected: (v) => setState(() => flaggedOnly = v),
        ),
        expand: true,
        child: list.isEmpty
            ? const Center(
                child: Text('Nothing to show', style: TextStyle(color: Palette.muted)),
              )
            : ListView.separated(
                itemCount: list.length,
                separatorBuilder: (_, _) => const Divider(height: 1, color: Palette.border),
                itemBuilder: (_, i) => ConnectionRow(x: list[i], dense: false),
              ),
      ),
    );
  }
}

/// Live log (design.screens.live_log): typed rows, timeline histogram, type filters, pause.
class LiveLogScreen extends StatefulWidget {
  const LiveLogScreen({super.key, required this.c});
  final DashboardController c;
  @override
  State<LiveLogScreen> createState() => _LiveLogScreenState();
}

const _types = {
  'flow': ('Flows', Icons.swap_horiz_rounded, Palette.accentGlow),
  'dns': ('DNS', Icons.dns_outlined, Palette.violet),
  'tls': ('TLS', Icons.lock_outline_rounded, Palette.green),
  'engine': ('Engine', Icons.memory_rounded, Palette.muted),
};

String _kind(String type) => type.startsWith('flow')
    ? 'flow'
    : type == 'dns'
    ? 'dns'
    : type.startsWith('tls')
    ? 'tls'
    : 'engine';

class _LiveLogScreenState extends State<LiveLogScreen> {
  final Set<String> hidden = {'engine'};

  @override
  Widget build(BuildContext context) {
    final c = widget.c;
    final rows = c.log.where((e) => !hidden.contains(_kind(e.type))).toList().reversed.toList();
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 4, 24, 24),
      child: GlassCard(
        title: 'Live log',
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            for (final e in _types.entries)
              Padding(
                padding: const EdgeInsets.only(left: 8),
                child: FilterChip(
                  label: Text(e.value.$1),
                  avatar: Icon(e.value.$2, size: 16, color: e.value.$3),
                  selected: !hidden.contains(e.key),
                  onSelected: (v) => setState(() => v ? hidden.remove(e.key) : hidden.add(e.key)),
                ),
              ),
            const SizedBox(width: 12),
            FilledButton.tonalIcon(
              onPressed: c.toggleLogPause,
              icon: Icon(c.logPaused ? Icons.play_arrow_rounded : Icons.pause_rounded, size: 18),
              label: Text(c.logPaused ? 'Resume (${c.pausedCount})' : 'Pause'),
            ),
          ],
        ),
        expand: true,
        child: Column(
          children: [
            _Timeline(entries: c.log),
            const SizedBox(height: 12),
            Expanded(
              child: rows.isEmpty
                  ? const Center(
                      child: Text('Waiting for events…', style: TextStyle(color: Palette.muted)),
                    )
                  : ListView.builder(
                      itemCount: rows.length,
                      itemBuilder: (_, i) => _LogRow(e: rows[i]),
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

class _LogRow extends StatelessWidget {
  const _LogRow({required this.e});
  final LogEntry e;
  @override
  Widget build(BuildContext context) {
    final t = _types[_kind(e.type)]!;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 70,
            child: Text(hhmmss(e.ts), style: const TextStyle(fontSize: 12, color: Palette.muted)),
          ),
          Container(
            width: 128,
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
            margin: const EdgeInsets.only(right: 12),
            decoration: BoxDecoration(
              color: t.$3.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Row(
              children: [
                Icon(t.$2, size: 13, color: t.$3),
                const SizedBox(width: 6),
                Flexible(
                  child: Text(
                    e.type,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(fontSize: 11, color: t.$3),
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: Text(e.summary, style: const TextStyle(fontSize: 13, color: Palette.text)),
          ),
        ],
      ),
    );
  }
}

/// Events per 10 s over the last 5 minutes.
class _Timeline extends StatelessWidget {
  const _Timeline({required this.entries});
  final List<LogEntry> entries;
  @override
  Widget build(BuildContext context) {
    final now = DateTime.now();
    final counts = List<int>.filled(30, 0);
    for (final e in entries) {
      final age = now.difference(e.ts).inSeconds;
      if (age >= 0 && age < 300) counts[29 - age ~/ 10]++;
    }
    final maxC = counts.reduce((a, b) => a > b ? a : b).clamp(1, 1 << 30);
    return SizedBox(
      height: 44,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          for (final n in counts)
            Expanded(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 1.5),
                child: Container(
                  height: 4 + 40 * n / maxC,
                  decoration: BoxDecoration(
                    color: Palette.accent.withValues(alpha: n == 0 ? 0.12 : 0.7),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
