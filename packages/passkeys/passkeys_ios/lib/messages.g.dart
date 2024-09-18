// Autogenerated from Pigeon (v11.0.1), do not edit directly.
// See also: https://pub.dev/packages/pigeon
// ignore_for_file: public_member_api_docs, non_constant_identifier_names, avoid_as, unused_import, unnecessary_parenthesis, prefer_null_aware_operators, omit_local_variable_types, unused_shown_name, unnecessary_import

import 'dart:async';
import 'dart:typed_data' show Float64List, Int32List, Int64List, Uint8List;

import 'package:flutter/foundation.dart' show ReadBuffer, WriteBuffer;
import 'package:flutter/services.dart';

/// Represents a relying party
class RelyingParty {
  RelyingParty({
    required this.name,
    required this.id,
  });

  /// Name of the relying party
  String name;

  /// ID of the relying party
  String id;

  Object encode() {
    return <Object?>[
      name,
      id,
    ];
  }

  static RelyingParty decode(Object result) {
    result as List<Object?>;
    return RelyingParty(
      name: result[0]! as String,
      id: result[1]! as String,
    );
  }
}

/// Represents a user
class User {
  User({
    required this.name,
    required this.id,
  });

  /// The name
  String name;

  /// The ID
  String id;

  Object encode() {
    return <Object?>[
      name,
      id,
    ];
  }

  static User decode(Object result) {
    result as List<Object?>;
    return User(
      name: result[0]! as String,
      id: result[1]! as String,
    );
  }
}

/// Represents a register response
class RegisterResponse {
  RegisterResponse({
    required this.id,
    required this.rawId,
    required this.clientDataJSON,
    required this.attestationObject,
  });

  /// The ID
  String id;

  /// The raw ID
  String rawId;

  /// The client data JSON
  String clientDataJSON;

  /// The attestation object
  String attestationObject;

  Object encode() {
    return <Object?>[
      id,
      rawId,
      clientDataJSON,
      attestationObject,
    ];
  }

  static RegisterResponse decode(Object result) {
    result as List<Object?>;
    return RegisterResponse(
      id: result[0]! as String,
      rawId: result[1]! as String,
      clientDataJSON: result[2]! as String,
      attestationObject: result[3]! as String,
    );
  }
}

/// Represents an authenticate response
class AuthenticateResponse {
  AuthenticateResponse({
    required this.id,
    required this.rawId,
    required this.clientDataJSON,
    required this.authenticatorData,
    required this.signature,
    required this.userHandle,
  });

  /// The ID
  String id;

  /// The raw ID
  String rawId;

  /// The client data JSON
  String clientDataJSON;

  /// The authenticator data
  String authenticatorData;

  /// Signed challenge
  String signature;

  String userHandle;

  Object encode() {
    return <Object?>[
      id,
      rawId,
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    ];
  }

  static AuthenticateResponse decode(Object result) {
    result as List<Object?>;
    return AuthenticateResponse(
      id: result[0]! as String,
      rawId: result[1]! as String,
      clientDataJSON: result[2]! as String,
      authenticatorData: result[3]! as String,
      signature: result[4]! as String,
      userHandle: result[5]! as String,
    );
  }
}

class _PasskeysApiCodec extends StandardMessageCodec {
  const _PasskeysApiCodec();
  @override
  void writeValue(WriteBuffer buffer, Object? value) {
    if (value is AuthenticateResponse) {
      buffer.putUint8(128);
      writeValue(buffer, value.encode());
    } else if (value is RegisterResponse) {
      buffer.putUint8(129);
      writeValue(buffer, value.encode());
    } else if (value is RelyingParty) {
      buffer.putUint8(130);
      writeValue(buffer, value.encode());
    } else if (value is User) {
      buffer.putUint8(131);
      writeValue(buffer, value.encode());
    } else {
      super.writeValue(buffer, value);
    }
  }

  @override
  Object? readValueOfType(int type, ReadBuffer buffer) {
    switch (type) {
      case 128: 
        return AuthenticateResponse.decode(readValue(buffer)!);
      case 129: 
        return RegisterResponse.decode(readValue(buffer)!);
      case 130: 
        return RelyingParty.decode(readValue(buffer)!);
      case 131: 
        return User.decode(readValue(buffer)!);
      default:
        return super.readValueOfType(type, buffer);
    }
  }
}

class PasskeysApi {
  /// Constructor for [PasskeysApi].  The [binaryMessenger] named argument is
  /// available for dependency injection.  If it is left null, the default
  /// BinaryMessenger will be used which routes to the host platform.
  PasskeysApi({BinaryMessenger? binaryMessenger})
      : _binaryMessenger = binaryMessenger;
  final BinaryMessenger? _binaryMessenger;

  static const MessageCodec<Object?> codec = _PasskeysApiCodec();

  Future<bool> canAuthenticate() async {
    final BasicMessageChannel<Object?> channel = BasicMessageChannel<Object?>(
        'dev.flutter.pigeon.passkeys_ios.PasskeysApi.canAuthenticate', codec,
        binaryMessenger: _binaryMessenger);
    final List<Object?>? replyList =
        await channel.send(null) as List<Object?>?;
    if (replyList == null) {
      throw PlatformException(
        code: 'channel-error',
        message: 'Unable to establish connection on channel.',
      );
    } else if (replyList.length > 1) {
      throw PlatformException(
        code: replyList[0]! as String,
        message: replyList[1] as String?,
        details: replyList[2],
      );
    } else if (replyList[0] == null) {
      throw PlatformException(
        code: 'null-error',
        message: 'Host platform returned null value for non-null return value.',
      );
    } else {
      return (replyList[0] as bool?)!;
    }
  }

  Future<RegisterResponse> register(String arg_challenge, RelyingParty arg_relyingParty, User arg_user, List<String?> arg_excludeCredentialIDs) async {
    final BasicMessageChannel<Object?> channel = BasicMessageChannel<Object?>(
        'dev.flutter.pigeon.passkeys_ios.PasskeysApi.register', codec,
        binaryMessenger: _binaryMessenger);
    final List<Object?>? replyList =
        await channel.send(<Object?>[arg_challenge, arg_relyingParty, arg_user, arg_excludeCredentialIDs]) as List<Object?>?;
    if (replyList == null) {
      throw PlatformException(
        code: 'channel-error',
        message: 'Unable to establish connection on channel.',
      );
    } else if (replyList.length > 1) {
      throw PlatformException(
        code: replyList[0]! as String,
        message: replyList[1] as String?,
        details: replyList[2],
      );
    } else if (replyList[0] == null) {
      throw PlatformException(
        code: 'null-error',
        message: 'Host platform returned null value for non-null return value.',
      );
    } else {
      return (replyList[0] as RegisterResponse?)!;
    }
  }

  Future<AuthenticateResponse> authenticate(String arg_relyingPartyId, String arg_challenge, bool arg_conditionalUI, List<String?> arg_allowedCredentialIDs) async {
    final BasicMessageChannel<Object?> channel = BasicMessageChannel<Object?>(
        'dev.flutter.pigeon.passkeys_ios.PasskeysApi.authenticate', codec,
        binaryMessenger: _binaryMessenger);
    final List<Object?>? replyList =
        await channel.send(<Object?>[arg_relyingPartyId, arg_challenge, arg_conditionalUI, arg_allowedCredentialIDs]) as List<Object?>?;
    if (replyList == null) {
      throw PlatformException(
        code: 'channel-error',
        message: 'Unable to establish connection on channel.',
      );
    } else if (replyList.length > 1) {
      throw PlatformException(
        code: replyList[0]! as String,
        message: replyList[1] as String?,
        details: replyList[2],
      );
    } else if (replyList[0] == null) {
      throw PlatformException(
        code: 'null-error',
        message: 'Host platform returned null value for non-null return value.',
      );
    } else {
      return (replyList[0] as AuthenticateResponse?)!;
    }
  }

  Future<void> cancelCurrentAuthenticatorOperation() async {
    final BasicMessageChannel<Object?> channel = BasicMessageChannel<Object?>(
        'dev.flutter.pigeon.passkeys_ios.PasskeysApi.cancelCurrentAuthenticatorOperation', codec,
        binaryMessenger: _binaryMessenger);
    final List<Object?>? replyList =
        await channel.send(null) as List<Object?>?;
    if (replyList == null) {
      throw PlatformException(
        code: 'channel-error',
        message: 'Unable to establish connection on channel.',
      );
    } else if (replyList.length > 1) {
      throw PlatformException(
        code: replyList[0]! as String,
        message: replyList[1] as String?,
        details: replyList[2],
      );
    } else {
      return;
    }
  }

  Future<void> goToSettings() async {
    final BasicMessageChannel<Object?> channel = BasicMessageChannel<Object?>(
        'dev.flutter.pigeon.passkeys_ios.PasskeysApi.goToSettings', codec,
        binaryMessenger: _binaryMessenger);
    final List<Object?>? replyList =
        await channel.send(null) as List<Object?>?;
    if (replyList == null) {
      throw PlatformException(
        code: 'channel-error',
        message: 'Unable to establish connection on channel.',
      );
    } else if (replyList.length > 1) {
      throw PlatformException(
        code: replyList[0]! as String,
        message: replyList[1] as String?,
        details: replyList[2],
      );
    } else {
      return;
    }
  }
}
