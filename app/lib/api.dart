import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'models.dart';

/// Client for the local REST API. Talks only to 127.0.0.1:8765 and reads the bearer token
/// from the file the API created ($XDG_DATA_HOME/silentsnake/config/api-token).
class ApiClient {
  ApiClient({this.host = '127.0.0.1', this.port = 8765});
  final String host;
  final int port;
  final HttpClient _http = HttpClient()..connectionTimeout = const Duration(seconds: 3);
  String? _token;

  static String tokenPath() {
    final env = Platform.environment;
    var base = env['XDG_DATA_HOME'] ?? '';
    if (base.isEmpty || !base.startsWith('/')) {
      base = '${env['HOME'] ?? ''}/.local/share';
    }
    return '$base/silentsnake/config/api-token';
  }

  Future<String> _loadToken() async {
    final t = _token;
    if (t != null) return t;
    final f = File(tokenPath());
    if (!await f.exists()) {
      throw const ApiException('No API token yet. Start the API first: silentsnake-api --interface any');
    }
    final v = (await f.readAsString()).trim();
    if (v.length != 64) throw const ApiException('API token file is malformed');
    return _token = v;
  }

  Uri _uri(String path, [Map<String, String>? q]) =>
      Uri(scheme: 'http', host: host, port: port, path: path, queryParameters: q);

  Future<HttpClientResponse> _get(String path, [Map<String, String>? q]) async {
    final token = await _loadToken();
    final HttpClientRequest req;
    try {
      req = await _http.getUrl(_uri(path, q));
    } on SocketException {
      throw ApiException('Cannot reach the SilentSnake API on $host:$port. Is silentsnake-api running?');
    }
    req.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
    final res = await req.close();
    if (res.statusCode == HttpStatus.unauthorized) {
      _token = null; // the API may have been re-initialised; re-read next time
      await res.drain<void>();
      throw const ApiException('The API rejected the token');
    }
    if (res.statusCode != HttpStatus.ok) {
      final body = await res.transform(utf8.decoder).join();
      throw ApiException('API error ${res.statusCode}: $body');
    }
    return res;
  }

  Future<Json> getJson(String path, [Map<String, String>? q]) async {
    final res = await _get(path, q);
    final body = await res.transform(utf8.decoder).join();
    final v = jsonDecode(body);
    if (v is! Map<String, Object?>) throw const ApiException('unexpected response');
    return v;
  }

  Future<List<Connection>> connections({String state = 'all', int limit = 200}) async {
    final j = await getJson('/v1/connections', {'state': state, 'limit': '$limit'});
    final list = j['connections'];
    return list is List ? list.whereType<Map<String, Object?>>().map(Connection.from).toList() : const [];
  }

  /// Server-Sent Events from /v1/stream as (event, data) pairs.
  Stream<(String, Json)> stream() async* {
    final res = await _get('/v1/stream');
    var event = 'message';
    final data = StringBuffer();
    await for (final line in res.transform(utf8.decoder).transform(const LineSplitter())) {
      if (line.isEmpty) {
        if (data.isNotEmpty) {
          final v = jsonDecode(data.toString());
          if (v is Map<String, Object?>) yield (event, v);
        }
        event = 'message';
        data.clear();
      } else if (line.startsWith('event:')) {
        event = line.substring(6).trim();
      } else if (line.startsWith('data:')) {
        data.write(line.substring(5).trimLeft());
      }
    }
  }

  void close() => _http.close(force: true);
}

class ApiException implements Exception {
  const ApiException(this.message);
  final String message;
  @override
  String toString() => message;
}
