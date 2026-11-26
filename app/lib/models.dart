// Typed views of the local REST API (docs/api/rest-api.md, silentsnake.api/1).
// Unknown fields are ignored; missing fields fall back to safe defaults.

typedef Json = Map<String, Object?>;

String _s(Json j, String k, [String d = '']) => j[k] is String ? j[k]! as String : d;
int _i(Json j, String k) => j[k] is num ? (j[k]! as num).toInt() : 0;
bool _b(Json j, String k) => j[k] == true;
DateTime? _t(Json j, String k) => j[k] is String ? DateTime.tryParse(j[k]! as String)?.toLocal() : null;
List<Json> _l(Json j, String k) =>
    j[k] is List ? (j[k]! as List).whereType<Map<String, Object?>>().toList() : const [];

class Endpoint {
  const Endpoint(this.ip, this.port);
  final String ip;
  final int port;
  static Endpoint? from(Object? v) => v is Map<String, Object?> ? Endpoint(_s(v, 'ip'), _i(v, 'port')) : null;
  @override
  String toString() => port == 0 ? ip : (ip.contains(':') ? '[$ip]:$port' : '$ip:$port');
}

class Risk {
  const Risk({required this.score, required this.level, required this.reasons});
  final int score;
  final String level; // low | guarded | elevated | high
  final List<String> reasons;
  factory Risk.from(Json j) => Risk(
    score: _i(j, 'score').clamp(0, 100),
    level: _s(j, 'level', 'low'),
    reasons: (j['reasons'] is List) ? (j['reasons']! as List).whereType<String>().toList() : const [],
  );
}

class Engine {
  const Engine({
    required this.running,
    required this.interface,
    required this.version,
    required this.startedAt,
    required this.packetsSeen,
    required this.bytesSeen,
    required this.flowsActive,
    required this.kernelDropped,
    required this.incomplete,
    required this.lastError,
  });
  final bool running;
  final String interface;
  final String version;
  final DateTime? startedAt;
  final int packetsSeen, bytesSeen, flowsActive, kernelDropped;
  final bool incomplete;
  final String lastError;
  factory Engine.from(Json j) => Engine(
    running: _b(j, 'running'),
    interface: _s(j, 'interface'),
    version: _s(j, 'version'),
    startedAt: _t(j, 'started_at'),
    packetsSeen: _i(j, 'packets_seen'),
    bytesSeen: _i(j, 'bytes_seen'),
    flowsActive: _i(j, 'flows_active'),
    kernelDropped: _i(j, 'kernel_dropped'),
    incomplete: _b(j, 'incomplete'),
    lastError: _s(j, 'last_error'),
  );
}

class Bucket {
  const Bucket(this.minute, this.bytes, this.flows);
  final DateTime minute;
  final int bytes, flows;
}

class Destination {
  const Destination(this.name, this.bytes, this.flows);
  final String name;
  final int bytes, flows;
}

class Overview {
  const Overview({
    required this.risk,
    required this.engine,
    required this.activeFlows,
    required this.flaggedFlows,
    required this.traffic,
    required this.topDestinations,
    required this.generatedAt,
  });
  final Risk risk;
  final Engine engine;
  final int activeFlows, flaggedFlows;
  final List<Bucket> traffic;
  final List<Destination> topDestinations;
  final DateTime generatedAt;

  factory Overview.from(Json j) => Overview(
    risk: Risk.from(j['risk'] is Map<String, Object?> ? j['risk']! as Json : const {}),
    engine: Engine.from(j['engine'] is Map<String, Object?> ? j['engine']! as Json : const {}),
    activeFlows: _i(j, 'active_flows'),
    flaggedFlows: _i(j, 'flagged_flows'),
    traffic: [
      for (final b in _l(j, 'traffic_per_minute'))
        Bucket(_t(b, 'minute') ?? DateTime.now(), _i(b, 'bytes'), _i(b, 'flows')),
    ],
    topDestinations: [
      for (final d in _l(j, 'top_destinations')) Destination(_s(d, 'name'), _i(d, 'bytes'), _i(d, 'flows')),
    ],
    generatedAt: _t(j, 'generated_at') ?? DateTime.now(),
  );
}

class Connection {
  const Connection({
    required this.id,
    required this.proto,
    required this.direction,
    required this.initiator,
    required this.responder,
    required this.service,
    required this.serverName,
    required this.started,
    required this.lastSeen,
    required this.ended,
    required this.bytesOut,
    required this.bytesIn,
    required this.risk,
    required this.reasons,
    required this.status,
    required this.summary,
  });
  final int id;
  final String proto, direction, service, serverName, status, summary;
  final Endpoint? initiator, responder;
  final DateTime? started, lastSeen;
  final bool ended;
  final int bytesOut, bytesIn, risk;
  final List<String> reasons;

  bool get flagged => status == 'flagged';

  /// The other end as the user thinks of it: the remote initiator for inbound traffic.
  String get peer {
    if (direction == 'inbound') return initiator?.toString() ?? '?';
    if (serverName.isNotEmpty) return serverName;
    return responder?.toString() ?? '?';
  }

  factory Connection.from(Json j) => Connection(
    id: _i(j, 'flow_id'),
    proto: _s(j, 'proto'),
    direction: _s(j, 'direction', 'unknown'),
    initiator: Endpoint.from(j['initiator']),
    responder: Endpoint.from(j['responder']),
    service: _s(j, 'service'),
    serverName: _s(j, 'server_name'),
    started: _t(j, 'started'),
    lastSeen: _t(j, 'last_seen'),
    ended: _b(j, 'ended'),
    bytesOut: _i(j, 'initiator_bytes'),
    bytesIn: _i(j, 'responder_bytes'),
    risk: _i(j, 'risk'),
    reasons: (j['risk_reasons'] is List)
        ? (j['risk_reasons']! as List).whereType<String>().toList()
        : const [],
    status: _s(j, 'status', 'allowed'),
    summary: _s(j, 'summary'),
  );
}

class LogEntry {
  const LogEntry(this.seq, this.ts, this.type, this.summary);
  final int seq;
  final DateTime ts;
  final String type, summary;
  factory LogEntry.from(Json j) =>
      LogEntry(_i(j, 'seq'), _t(j, 'ts') ?? DateTime.now(), _s(j, 'type'), _s(j, 'summary'));
}

String formatBytes(int b) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var v = b.toDouble();
  var u = 0;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u++;
  }
  return u == 0 ? '$b B' : '${v.toStringAsFixed(v >= 100 ? 0 : 1)} ${units[u]}';
}

String two(int n) => n.toString().padLeft(2, '0');
String hhmm(DateTime t) => '${two(t.hour)}:${two(t.minute)}';
String hhmmss(DateTime t) => '${hhmm(t)}:${two(t.second)}';
