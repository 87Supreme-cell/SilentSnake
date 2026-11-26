// ignore: deprecated_member_use
import 'package:flutter/material.dart';

import 'controller.dart';
import 'models.dart';
import 'theme.dart';
import 'widgets.dart';

/// One-screen real-time overview (silentsnake.yaml design.screens.dashboard).
class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key, required this.c});
  final DashboardController c;

  @override
  Widget build(BuildContext context) {
    final o = c.overview;
    return LayoutBuilder(
      builder: (context, box) {
        final wide = box.maxWidth >= 900;
        Widget row(Widget a, Widget b) => wide
            ? IntrinsicHeight(
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Expanded(flex: 3, child: a),
                    const SizedBox(width: 18),
                    Expanded(flex: 2, child: b),
                  ],
                ),
              )
            : Column(children: [a, const SizedBox(height: 18), b]);
        return ListView(
          padding: const EdgeInsets.fromLTRB(4, 4, 24, 24),
          children: [
            if (!c.connected) ...[_Disconnected(c.error), const SizedBox(height: 18)],
            row(_Hero(c: c), _EngineCard(o: o)),
            const SizedBox(height: 18),
            row(_RiskCard(o: o), const _DeepScanCard()),
            const SizedBox(height: 18),
            row(_LiveConnections(c: c), _AlertsCard(o: o, c: c)),
            const SizedBox(height: 18),
            row(_TrafficCard(o: o), _PeersCard(o: o)),
          ],
        );
      },
    );
  }
}

class _Disconnected extends StatelessWidget {
  const _Disconnected(this.error);
  final String? error;
  @override
  Widget build(BuildContext context) => GlassCard(
    child: Row(
      children: [
        const Icon(Icons.link_off_rounded, color: Palette.orange),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            error ?? 'Connecting to the SilentSnake API…',
            style: const TextStyle(color: Palette.text, fontSize: 14),
          ),
        ),
        const Text('retrying every 3 s', style: TextStyle(color: Palette.muted, fontSize: 12)),
      ],
    ),
  );
}

class _Hero extends StatelessWidget {
  const _Hero({required this.c});
  final DashboardController c;
  @override
  Widget build(BuildContext context) {
    final o = c.overview;
    final now = DateTime.now();
    final tp = c.throughput;
    final rate = tp.isEmpty ? 0 : tp.last.round();
    return GlassCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      o == null
                          ? 'Waiting for data'
                          : (o.engine.running ? 'Watching live traffic' : 'Monitoring stopped'),
                      style: const TextStyle(fontSize: 14, color: Palette.muted),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '${formatBytes(rate)}/s',
                      style: const TextStyle(fontSize: 34, fontWeight: FontWeight.w700, color: Palette.text),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      o == null
                          ? '—'
                          : '${o.activeFlows} active connections · ${formatBytes(o.engine.bytesSeen)} seen this session',
                      style: const TextStyle(fontSize: 13, color: Palette.muted),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: const Color(0x14FFFFFF),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: Palette.border),
                ),
                child: Text(hhmm(now), style: const TextStyle(fontSize: 13, color: Palette.text)),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Sparkline(values: tp),
        ],
      ),
    );
  }
}

class _EngineCard extends StatelessWidget {
  const _EngineCard({required this.o});
  final Overview? o;
  @override
  Widget build(BuildContext context) {
    final e = o?.engine;
    final ok = e != null && e.running && !e.incomplete;
    final pill = e == null
        ? const StatusPill(label: 'Unknown', color: Palette.muted, icon: Icons.help_outline)
        : !e.running
        ? const StatusPill(label: 'Stopped', color: Palette.red, icon: Icons.stop_circle_outlined)
        : e.incomplete
        ? const StatusPill(
            label: 'Dropping packets',
            color: Palette.orange,
            icon: Icons.warning_amber_rounded,
          )
        : const StatusPill(label: 'Capturing', color: Palette.green, icon: Icons.radar_rounded);
    return GlassCard(
      title: 'Capture engine',
      trailing: pill,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            e == null
                ? 'No data yet'
                : 'Interface ${e.interface}${e.version.isEmpty ? '' : ' · v${e.version}'}'
                      '${e.startedAt == null ? '' : ' · since ${hhmm(e.startedAt!)}'}',
            style: const TextStyle(fontSize: 13, color: Palette.muted),
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 28,
            runSpacing: 14,
            children: [
              Stat('Packets', e == null ? '—' : '${e.packetsSeen}'),
              Stat('Dropped', e == null ? '—' : '${e.kernelDropped}', color: ok ? null : Palette.orange),
              Stat('Flows', e == null ? '—' : '${e.flowsActive}'),
            ],
          ),
          if (e != null && e.lastError.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(e.lastError, style: const TextStyle(fontSize: 12, color: Palette.orange)),
          ],
          if (e != null && e.incomplete) ...[
            const SizedBox(height: 12),
            const Text(
              'Some packets were dropped, so this record is incomplete.',
              style: TextStyle(fontSize: 12, color: Palette.orange),
            ),
          ],
        ],
      ),
    );
  }
}

class _RiskCard extends StatelessWidget {
  const _RiskCard({required this.o});
  final Overview? o;
  @override
  Widget build(BuildContext context) {
    final r = o?.risk;
    final st = RiskStyle.of(r?.level ?? 'low');
    return GlassCard(
      title: 'Risk',
      trailing: const Text('last 5 min', style: TextStyle(fontSize: 12, color: Palette.muted)),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.baseline,
                  textBaseline: TextBaseline.alphabetic,
                  children: [
                    Text(
                      r == null ? '—' : '${r.score}',
                      style: const TextStyle(fontSize: 52, fontWeight: FontWeight.w700, color: Palette.text),
                    ),
                    const SizedBox(width: 4),
                    const Text('/100', style: TextStyle(fontSize: 16, color: Palette.muted)),
                  ],
                ),
                const SizedBox(height: 8),
                StatusPill(label: st.label, color: st.color, icon: st.icon),
                const SizedBox(height: 16),
                Wrap(
                  spacing: 28,
                  children: [
                    Stat(
                      'Flagged',
                      o == null ? '—' : '${o!.flaggedFlows}',
                      color: (o?.flaggedFlows ?? 0) > 0 ? Palette.orange : null,
                    ),
                    Stat('Active', o == null ? '—' : '${o!.activeFlows}'),
                  ],
                ),
              ],
            ),
          ),
          Semantics(
            label: 'Risk score ${r?.score ?? 0} of 100, ${st.label}',
            child: Stack(
              alignment: Alignment.center,
              children: [
                RiskRing(score: r?.score ?? 0, color: st.color),
                Icon(st.icon, color: st.color, size: 34),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _DeepScanCard extends StatelessWidget {
  const _DeepScanCard();
  @override
  Widget build(BuildContext context) => GlassCard(
    title: 'Deep scan',
    child: Column(
      children: [
        const SizedBox(height: 6),
        const Stack(
          alignment: Alignment.center,
          children: [
            RiskRing(score: 0, color: Palette.faint, size: 128),
            Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  '00:00',
                  style: TextStyle(fontSize: 28, fontWeight: FontWeight.w600, color: Palette.muted),
                ),
                Text('not available', style: TextStyle(fontSize: 11, color: Palette.faint)),
              ],
            ),
          ],
        ),
        const SizedBox(height: 14),
        Tooltip(
          message:
              'Deep scan needs the encrypted log store (not built yet). '
              'Start and stop will always ask you to confirm.',
          child: OutlinedButton.icon(
            onPressed: null,
            icon: const Icon(Icons.play_arrow_rounded, size: 18),
            label: const Text('Start'),
          ),
        ),
      ],
    ),
  );
}

class _LiveConnections extends StatelessWidget {
  const _LiveConnections({required this.c});
  final DashboardController c;
  @override
  Widget build(BuildContext context) {
    final list = [...c.connections.where((x) => !x.ended), ...c.connections.where((x) => x.ended)];
    list.sort((a, b) {
      final r = b.risk.compareTo(a.risk);
      if (r != 0) return r;
      return (b.lastSeen ?? DateTime(0)).compareTo(a.lastSeen ?? DateTime(0));
    });
    final shown = list.take(7).toList();
    return GlassCard(
      title: 'Live connections',
      trailing: Text(
        '${c.connections.where((x) => !x.ended).length} active',
        style: const TextStyle(fontSize: 12, color: Palette.muted),
      ),
      child: shown.isEmpty
          ? const Padding(
              padding: EdgeInsets.symmetric(vertical: 24),
              child: Text('No connections yet', style: TextStyle(color: Palette.muted)),
            )
          : Column(children: [for (final x in shown) ConnectionRow(x: x)]),
    );
  }
}

class ConnectionRow extends StatelessWidget {
  const ConnectionRow({super.key, required this.x, this.dense = true});
  final Connection x;
  final bool dense;
  @override
  Widget build(BuildContext context) {
    final st = RiskStyle.forScore(x.risk);
    final service = x.service.isNotEmpty ? x.service : x.proto.toUpperCase();
    return Tooltip(
      message: [x.summary, ...x.reasons].where((s) => s.isNotEmpty).join('\n'),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 7),
        child: Row(
          children: [
            Semantics(
              label: x.direction,
              child: Icon(directionIcon(x.direction), size: 18, color: Palette.muted),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    x.peer,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 14, color: Palette.text),
                  ),
                  Text(
                    '$service · ${x.direction}${x.ended ? ' · ended' : ''}',
                    style: const TextStyle(fontSize: 11, color: Palette.muted),
                  ),
                ],
              ),
            ),
            if (!dense) ...[
              SizedBox(
                width: 90,
                child: Text(
                  x.ended ? formatBytes(x.bytesIn + x.bytesOut) : 'open',
                  textAlign: TextAlign.right,
                  style: const TextStyle(fontSize: 12, color: Palette.muted),
                ),
              ),
              const SizedBox(width: 16),
            ],
            SizedBox(
              width: 36,
              child: Text(
                '${x.risk}',
                textAlign: TextAlign.right,
                style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: st.color),
              ),
            ),
            const SizedBox(width: 12),
            x.flagged
                ? const StatusPill(label: 'Flagged', color: Palette.orange, icon: Icons.flag_rounded)
                : const StatusPill(label: 'Allowed', color: Palette.green, icon: Icons.check_rounded),
          ],
        ),
      ),
    );
  }
}

class _AlertsCard extends StatelessWidget {
  const _AlertsCard({required this.o, required this.c});
  final Overview? o;
  final DashboardController c;
  @override
  Widget build(BuildContext context) {
    final reasons = o?.risk.reasons ?? const [];
    final flagged = c.connections.where((x) => x.flagged).take(4).toList();
    return GlassCard(
      title: 'Alerts',
      trailing: Text(
        '${reasons.length + flagged.length}',
        style: const TextStyle(fontSize: 12, color: Palette.muted),
      ),
      child: reasons.isEmpty && flagged.isEmpty
          ? const Row(
              children: [
                Icon(Icons.check_circle_outline_rounded, color: Palette.green, size: 20),
                SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Nothing needs your attention right now.',
                    style: TextStyle(fontSize: 13, color: Palette.text),
                  ),
                ),
              ],
            )
          : Column(
              children: [
                for (final r in reasons) _Alert(title: 'Why the score is ${o!.risk.score}', body: r),
                for (final f in flagged) _Alert(title: 'Flagged: ${f.peer}', body: f.reasons.join('; ')),
              ],
            ),
    );
  }
}

class _Alert extends StatelessWidget {
  const _Alert({required this.title, required this.body});
  final String title, body;
  @override
  Widget build(BuildContext context) => Theme(
    data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
    child: ExpansionTile(
      tilePadding: EdgeInsets.zero,
      dense: true,
      leading: const Icon(Icons.info_outline_rounded, color: Palette.yellow, size: 20),
      title: Text(title, style: const TextStyle(fontSize: 13, color: Palette.text)),
      subtitle: Text(
        body,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(fontSize: 12, color: Palette.muted),
      ),
      childrenPadding: const EdgeInsets.only(left: 40, bottom: 8),
      children: [
        Align(
          alignment: Alignment.centerLeft,
          child: Text(body, style: const TextStyle(fontSize: 12, color: Palette.text)),
        ),
      ],
    ),
  );
}

class _TrafficCard extends StatelessWidget {
  const _TrafficCard({required this.o});
  final Overview? o;
  @override
  Widget build(BuildContext context) {
    final b = o?.traffic ?? const <Bucket>[];
    final total = b.fold<int>(0, (s, x) => s + x.bytes);
    return GlassCard(
      title: 'Traffic activity',
      trailing: Text(
        'per minute · ${formatBytes(total)} in ${b.length} min',
        style: const TextStyle(fontSize: 12, color: Palette.muted),
      ),
      child: BarChart(buckets: b.length > 30 ? b.sublist(b.length - 30) : b),
    );
  }
}

class _PeersCard extends StatelessWidget {
  const _PeersCard({required this.o});
  final Overview? o;
  @override
  Widget build(BuildContext context) {
    final d = o?.topDestinations ?? const <Destination>[];
    final maxB = d.isEmpty ? 1 : d.first.bytes.clamp(1, 1 << 62);
    return GlassCard(
      title: 'Top peers',
      trailing: const Tooltip(
        message: 'Per-process view arrives with process attribution (stage C).',
        child: Text('by bytes', style: TextStyle(fontSize: 12, color: Palette.muted)),
      ),
      child: d.isEmpty
          ? const Text('No traffic yet', style: TextStyle(color: Palette.muted))
          : Column(
              children: [
                for (final x in d.take(6))
                  HBar(label: x.name, value: formatBytes(x.bytes), fraction: x.bytes / maxB),
              ],
            ),
    );
  }
}
