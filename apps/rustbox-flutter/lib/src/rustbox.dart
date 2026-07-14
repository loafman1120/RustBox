import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import 'rust/api/engine.dart' as native;
import 'rust/frb_generated.dart';

/// Initializes the Rust bridge once for the current process.
abstract final class RustBox {
  static Future<void>? _initialization;

  static Future<void> initialize() => _initialization ??= RustLib.init(
    externalLibrary: Platform.isIOS || Platform.isMacOS
        ? ExternalLibrary.process(iKnowHowToUseIt: true)
        : null,
  );
}

enum RustBoxExceptionKind {
  invalidConfig,
  invalidState,
  unavailable,
  runtime,
  internal,
}

final class RustBoxException implements Exception {
  const RustBoxException(this.kind, this.message);

  final RustBoxExceptionKind kind;
  final String message;

  @override
  String toString() => 'RustBoxException(${kind.name}): $message';
}

enum RustBoxEngineState {
  created,
  prepared,
  running,
  stopping,
  stopped,
  failed,
}

final class RustBoxEngineSnapshot {
  const RustBoxEngineSnapshot({
    required this.state,
    required this.generation,
    required this.inboundCount,
    required this.outboundCount,
  });

  final RustBoxEngineState state;
  final int generation;
  final int inboundCount;
  final int outboundCount;
}

/// A Dart-owned handle to one serialized RustBox engine instance.
final class RustBoxEngine {
  RustBoxEngine._(this._native);

  final native.NativeRustBoxEngine _native;
  Future<void>? _closeFuture;
  bool _closing = false;

  static Future<RustBoxEngine> create({required String configToml}) async {
    await RustBox.initialize();
    final engine = await _translate(
      () => native.NativeRustBoxEngine.create(configToml: configToml),
    );
    return RustBoxEngine._(engine);
  }

  Future<void> start() {
    _ensureOpen();
    return _translate(_native.start);
  }

  Future<void> reload(String configToml) {
    _ensureOpen();
    return _translate(() => _native.reload(configToml: configToml));
  }

  Future<RustBoxEngineSnapshot> snapshot() {
    _ensureOpen();
    return _translate(_native.snapshot).then(_snapshotFromNative);
  }

  Future<void> stop() {
    _ensureOpen();
    return _translate(_native.stop);
  }

  /// Stops the engine and releases its opaque native handle.
  Future<void> close() {
    final current = _closeFuture;
    if (current != null) {
      return current;
    }
    _closing = true;
    return _closeFuture = _close();
  }

  Future<void> _close() async {
    try {
      await _translate(_native.shutdown);
    } finally {
      _native.dispose();
    }
  }

  void _ensureOpen() {
    if (_closing) {
      throw const RustBoxException(
        RustBoxExceptionKind.unavailable,
        'RustBox engine is closed',
      );
    }
  }
}

Future<T> _translate<T>(Future<T> Function() operation) async {
  try {
    return await operation();
  } on native.BridgeError catch (error) {
    throw RustBoxException(_errorKindFromNative(error.kind), error.message);
  } on RustBoxException {
    rethrow;
  } catch (error) {
    throw RustBoxException(RustBoxExceptionKind.internal, error.toString());
  }
}

RustBoxExceptionKind _errorKindFromNative(native.BridgeErrorKind kind) {
  return switch (kind) {
    native.BridgeErrorKind.invalidConfig => RustBoxExceptionKind.invalidConfig,
    native.BridgeErrorKind.invalidState => RustBoxExceptionKind.invalidState,
    native.BridgeErrorKind.unavailable => RustBoxExceptionKind.unavailable,
    native.BridgeErrorKind.runtime => RustBoxExceptionKind.runtime,
  };
}

RustBoxEngineSnapshot _snapshotFromNative(
  native.BridgeEngineSnapshot snapshot,
) {
  return RustBoxEngineSnapshot(
    state: RustBoxEngineState.values[snapshot.state.index],
    generation: snapshot.generation.toInt(),
    inboundCount: snapshot.inboundCount.toInt(),
    outboundCount: snapshot.outboundCount.toInt(),
  );
}
