import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart';
import 'package:http_parser/http_parser.dart';

/// Blob type
enum BlobType {
  blockBlob('BlockBlob'),
  appendBlob('AppendBlob');

  const BlobType(this.displayName);

  final String displayName;
}

/// Azure Storage Exception
class AzureStorageException implements Exception {
  final String message;
  final int statusCode;
  final Map<String, String> headers;

  AzureStorageException(this.message, this.statusCode, this.headers);
}

/// Azure Storage Exception
class ConnectionStringParseException implements Exception {
  final String message;
  final String connectionString;

  ConnectionStringParseException(this.message, this.connectionString);
}

/// Azure Storage Client
class AzureStorage {
  late Map<String, String> config;
  late Uint8List accountKeyBytes;

  static const String defaultEndpointsProtocol = 'DefaultEndpointsProtocol';
  static const String endpointSuffix = 'EndpointSuffix';
  static const String accountName = 'AccountName';
  static const String accountKey = 'AccountKey';

  /// Initialize with connection string.
  AzureStorage.parse(String connectionString) {
    try {
      Map<String, String> m = <String, String>{};
      final List<String> items = connectionString.split(';');
      for (final String item in items) {
        final int i = item.indexOf('=');
        final String key = item.substring(0, i);
        final String val = item.substring(i + 1);
        m[key] = val;
      }
      config = m;
      accountKeyBytes = base64Decode(config[accountKey]!);
    } on Exception catch (e) {
      throw throw ConnectionStringParseException(
        connectionString,
        'Failed to parse connection string: $e',
      );
    }
  }

  @override
  String toString() {
    return config.toString();
  }

  Uri uri({String path = '/', Map<String, String>? queryParameters}) {
    final String? blobEndpoint = config['BlobEndpoint'];
    // TODO(Triqoz): This needs to be revisited in the context of azurite.
    if (blobEndpoint != null) {
      // Parse from explicit endpoint (like Azurite's BlobEndpoint)
      final Uri base = Uri.parse(blobEndpoint);
      return base.replace(
        path: '${base.path}$path',
        queryParameters: queryParameters,
      );
    }

    final String scheme = config[defaultEndpointsProtocol] ?? 'https';
    final String suffix = config[endpointSuffix] ?? 'core.windows.net';
    final String? name = config[accountName];
    // TODO(Triqoz): With name being nullable this might go very wrong for azurite
    return Uri(
      scheme: scheme,
      host: '$name.blob.$suffix',
      path: path,
      queryParameters: queryParameters,
    );
  }

  String _canonicalHeaders(Map<String, String> headers) {
    final List<String> keys = headers.keys
        .where((i) => i.startsWith('x-ms-'))
        .map((i) => '$i:${headers[i]}\n')
        .toList();
    keys.sort();
    return keys.join();
  }

  String _canonicalResources(Map<String, String> items) {
    if (items.isEmpty) {
      return '';
    }
    final List<String> keys = items.keys.toList()..sort();
    return keys.map((i) => '\n$i:${items[i]}').join();
  }

  void sign(http.Request request) {
    request.headers['x-ms-date'] = formatHttpDate(DateTime.now());
    request.headers['x-ms-version'] = '2019-12-12';
    final String ce = request.headers['Content-Encoding'] ?? '';
    final String cl = request.headers['Content-Language'] ?? '';
    final String cz = request.contentLength == 0
        ? ''
        : '${request.contentLength}';
    final String cm = request.headers['Content-MD5'] ?? '';
    final String ct = request.headers['Content-Type'] ?? '';
    final String dt = request.headers['Date'] ?? '';
    final String ims = request.headers['If-Modified-Since'] ?? '';
    final String imt = request.headers['If-Match'] ?? '';
    final String inm = request.headers['If-None-Match'] ?? '';
    final String ius = request.headers['If-Unmodified-Since'] ?? '';
    final String ran = request.headers['Range'] ?? '';
    final String chs = _canonicalHeaders(request.headers);
    final String crs = _canonicalResources(request.url.queryParameters);
    final String? name = config[accountName];
    final String path = request.url.path;
    final String sig =
        '${request.method}\n$ce\n$cl\n$cz\n$cm\n$ct\n$dt\n$ims\n$imt\n$inm\n$ius\n$ran\n$chs/$name$path$crs';
    final Hmac mac = crypto.Hmac(crypto.sha256, accountKeyBytes);
    final String digest = base64Encode(mac.convert(utf8.encode(sig)).bytes);
    final String auth = 'SharedKey $name:$digest';
    request.headers['Authorization'] = auth;
  }

  (String, String?) _splitPathSegment(String path) {
    final p = path.startsWith('/') ? path.substring(1) : path;
    final i = p.indexOf('/');
    if (i < 0 || p.length < i + 2) {
      return (p, null);
    }
    return (p.substring(0, i), p.substring(i + 1));
  }

  /// Close internal http client.
  void close({bool force = false}) {
    // do nothing. just for backward compatibility.
  }

  /// List Blobs. (Raw API)
  ///
  /// You cat use `await response.stream.bytesToString();` to get blob listing as XML format.
  Future<http.StreamedResponse> listBlobsRaw(String path) async {
    final (String container, String? rest) = _splitPathSegment(path);
    final Request request = http.Request(
      'GET',
      uri(
        path: container,
        queryParameters: {
          "restype": "container",
          "comp": "list",
          "prefix": ?rest,
        },
      ),
    );
    sign(request);
    return request.send();
  }

  /// Get Blob.
  Future<http.StreamedResponse> getBlob(String path) async {
    final Request request = http.Request('GET', uri(path: path));
    sign(request);
    return request.send();
  }

  /// Delete Blob
  Future<http.StreamedResponse> deleteBlob(String path) async {
    final Request request = http.Request('DELETE', uri(path: path));
    sign(request);
    return request.send();
  }

  String _signedExpiry(DateTime? expiry) {
    final String expiryString =
        (expiry ?? DateTime.now().add(const Duration(hours: 1)))
            .toUtc()
            .toIso8601String();
    return '${expiryString.substring(0, expiryString.indexOf('.'))}Z';
  }

  /// Get Blob Link.
  Future<Uri> getBlobLink(String path, {DateTime? expiry}) async {
    final String signedPermissions = 'r';
    final String signedStart = '';
    final String signedExpiry = _signedExpiry(expiry);
    final String signedIdentifier = '';
    final String signedVersion = '2012-02-12';
    final String? name = config[accountName];
    final String canonicalizedResource = '/$name$path';
    final String sigStr =
        '$signedPermissions\n'
        '$signedStart\n'
        '$signedExpiry\n'
        '$canonicalizedResource\n'
        '$signedIdentifier\n'
        '$signedVersion';
    final Hmac mac = crypto.Hmac(crypto.sha256, accountKeyBytes);
    final String sig = base64Encode(mac.convert(utf8.encode(sigStr)).bytes);
    return uri(
      path: path,
      queryParameters: {
        'sr': 'b',
        'sp': signedPermissions,
        'se': signedExpiry,
        'sv': signedVersion,
        'spr': 'https',
        'sig': sig,
      },
    );
  }

  /// Put Blob.
  ///
  /// `body` and `bodyBytes` are exclusive and mandatory.
  Future<void> putBlob(
    String path, {
    String? body,
    Uint8List? bodyBytes,
    String? contentType,
    BlobType type = BlobType.blockBlob,
    Map<String, String>? headers,
  }) async {
    if (body == null && bodyBytes == null) {
      throw ArgumentError('body or bodyBytes is required.');
    }

    if (body != null && bodyBytes != null) {
      throw ArgumentError(
        'body and bodyBytes are exclusive, pass only one of them.',
      );
    }

    final Request request = http.Request('PUT', uri(path: path));
    request.headers['x-ms-blob-type'] = type.displayName;
    if (headers != null) {
      headers.forEach((key, value) {
        request.headers['x-ms-meta-$key'] = value;
      });
    }
    if (contentType != null) {
      request.headers['content-type'] = contentType;
    }
    if (type == BlobType.blockBlob) {
      if (bodyBytes != null) {
        request.bodyBytes = bodyBytes;
      } else if (body != null) {
        request.body = body;
      }
    } else {
      request.body = '';
    }
    sign(request);
    final StreamedResponse res = await request.send();

    if (res.statusCode != 201) {
      final String message = await res.stream.bytesToString();
      throw AzureStorageException(message, res.statusCode, res.headers);
    }

    await res.stream.drain();
    if (type == BlobType.appendBlob && (body != null || bodyBytes != null)) {
      await appendBlock(path, body: body, bodyBytes: bodyBytes);
    }
  }

  /// Append block to blob.
  Future<void> appendBlock(
    String path, {
    String? body,
    Uint8List? bodyBytes,
  }) async {
    if (body == null && bodyBytes == null) {
      throw ArgumentError('body or bodyBytes is required.');
    }

    if (body != null && bodyBytes != null) {
      throw ArgumentError(
        'body and bodyBytes are exclusive, pass only one of them.',
      );
    }

    final Request request = http.Request(
      'PUT',
      uri(path: path, queryParameters: {'comp': 'appendblock'}),
    );
    if (bodyBytes != null) {
      request.bodyBytes = bodyBytes;
    } else if (body != null) {
      request.body = body;
    }
    sign(request);
    final StreamedResponse res = await request.send();
    if (res.statusCode == 201) {
      await res.stream.drain();
      return;
    }

    final String message = await res.stream.bytesToString();
    throw AzureStorageException(message, res.statusCode, res.headers);
  }
}
