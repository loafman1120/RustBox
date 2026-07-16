import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import 'rust/api/engine.dart' as native;
import 'rust/frb_generated.dart';

/// Entry point for initializing the RustBox native runtime.
abstract final class RustBox {
  static Future<void>? _initialization;

  /// Loads the bundled native library and initializes the bridge.
  ///
  /// Calling this method more than once returns the same initialization future.
  static Future<void> initialize() => _initialization ??= RustLib.init(
    externalLibrary: Platform.isIOS || Platform.isMacOS
        ? ExternalLibrary.process(iKnowHowToUseIt: true)
        : null,
  );
}

/// Stable categories for failures reported by the RustBox runtime.
enum RustBoxExceptionKind {
  /// The supplied TOML configuration is invalid.
  invalidConfig,

  /// The requested operation is not valid in the engine's current state.
  invalidState,

  /// A required native resource or service is unavailable.
  unavailable,

  /// The native proxy runtime failed while performing an operation.
  runtime,

  /// The bridge encountered an unexpected failure.
  internal,
}

/// An error raised by a RustBox engine or by the native bridge.
final class RustBoxException implements Exception {
  /// Creates an exception with a stable [kind] and human-readable [message].
  const RustBoxException(this.kind, this.message);

  /// The machine-readable failure category.
  final RustBoxExceptionKind kind;

  /// A human-readable description of the failure.
  final String message;

  @override
  String toString() => 'RustBoxException(${kind.name}): $message';
}

/// Lifecycle states reported by [RustBoxEngine.snapshot].
enum RustBoxEngineState {
  /// The native engine has been allocated but not prepared.
  created,

  /// Configuration is valid and the engine is ready to start.
  prepared,

  /// Inbound services are running.
  running,

  /// The engine is shutting down its services.
  stopping,

  /// All engine services have stopped.
  stopped,

  /// The engine entered a terminal failure state.
  failed,
}

/// A point-in-time view of a RustBox engine's lifecycle and topology.
final class RustBoxEngineSnapshot {
  /// Creates an immutable engine snapshot.
  const RustBoxEngineSnapshot({
    required this.state,
    required this.generation,
    required this.inboundCount,
    required this.outboundCount,
  });

  /// The lifecycle state observed when the snapshot was taken.
  final RustBoxEngineState state;

  /// The configuration generation, incremented after each successful reload.
  final int generation;

  /// The number of configured inbound services.
  final int inboundCount;

  /// The number of configured outbound adapters.
  final int outboundCount;
}

/// A Dart-owned handle to one serialized RustBox engine instance.
final class RustBoxEngine {
  RustBoxEngine._(this._native);

  final native.NativeRustBoxEngine _native;
  Future<void>? _closeFuture;
  bool _closing = false;

  /// Creates and prepares an engine from a RustBox TOML configuration.
  ///
  /// The returned engine is not running until [start] is called.
  static Future<RustBoxEngine> create({required String configToml}) async {
    await RustBox.initialize();
    final engine = await _translate(
      () => native.NativeRustBoxEngine.create(configToml: configToml),
    );
    return RustBoxEngine._(engine);
  }

  /// Starts all configured inbound services.
  Future<void> start() {
    _ensureOpen();
    return _translate(_native.start);
  }

  /// Atomically replaces the active configuration with [configToml].
  Future<void> reload(String configToml) {
    _ensureOpen();
    return _translate(() => _native.reload(configToml: configToml));
  }

  /// Returns the engine's current lifecycle and configuration snapshot.
  Future<RustBoxEngineSnapshot> snapshot() {
    _ensureOpen();
    return _translate(_native.snapshot).then(_snapshotFromNative);
  }

  /// Stops all running services while retaining the native engine handle.
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
