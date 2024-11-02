import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:js/js_util.dart';
import 'package:passkeys_platform_interface/passkeys_platform_interface.dart';
import 'package:passkeys_platform_interface/types/types.dart';
import 'package:passkeys_web/interop.dart';
import 'package:passkeys_web/models/passkeyLoginRequest.dart';
import 'package:passkeys_web/models/passkeyLoginResponse.dart';
import 'package:passkeys_web/models/passkeySignUpRequest.dart';
import 'package:passkeys_web/models/passkeySignUpResponse.dart';

/// The Web implementation of [PasskeysPlatform].
class PasskeysWeb extends PasskeysPlatform {
  /// Registers this class as the default instance of [PasskeysPlatform]
  static void registerWith([Object? registrar]) {
    PasskeysPlatform.instance = PasskeysWeb();
    init();
  }

  @override
  Future<bool> canAuthenticate() {
    return Future.value(true);
  }

  @override
  Future<RegisterResponseType> register(RegisterRequestType request) async {
    final r = PasskeySignUpRequest(
      PublicKey(
        request.relyingParty,
        request.user,
        request.challenge,
        request.pubKeyCredParams!,
        request.authSelectionType,
        request.excludeCredentials,
        request.timeout,
      ),
    );

    try {
      final serializedRequest = jsonEncode(r.toJson());
      final response = await promiseToFuture<String>(
          authenticatorRegister(serializedRequest));
      final decodedResponse =
          jsonDecode(response) as Map<String, dynamic>;
      final typedResponse = PasskeySignUpResponse.fromJson(decodedResponse);

      return RegisterResponseType(
        id: typedResponse.id,
        rawId: typedResponse.rawId,
        clientDataJSON: typedResponse.response.clientDataJSON,
        attestationObject: typedResponse.response.attestationObject,
      );
    } catch (e) {
      final exception = _parseException(e as String);
      throw exception;
    }
  }

  @override
  Future<AuthenticateResponseType> authenticate(
      AuthenticateRequestType request) async {
    final r = PasskeyLoginRequest.fromPlatformType(
      request.relyingPartyId,
      request.challenge,
      request.timeout,
      request.userVerification,
      request.allowCredentials,
      request.mediation,
    );

    try {
      final serializedRequest = jsonEncode(r.toJson());
      final response =
          await promiseToFuture<String>(authenticatorLogin(serializedRequest));
      final decodedResponse = jsonDecode(response) as Map<String, dynamic>;
      final typedResponse = PasskeyLoginResponse.fromJson(decodedResponse);

      return typedResponse.toAuthenticateResponseType();
    } catch (e) {
      final exception = _parseException(e as String);
      throw exception;
    }
  }

  PlatformException _parseException(String exception) {
    try {
      final decoded = jsonDecode(exception) as Map<String, dynamic>;
      final code = decoded['code'] as String;
      final message = decoded['message'] as String;
      final details = decoded['details'] as String;
      return PlatformException(code: code, message: message, details: details);
    } catch (e) {
      return PlatformException(
        code: 'parse-error',
        message: 'Could not parse exception: $e',
        details: exception,
      );
    }
  }

  @override
  Future<void> cancelCurrentAuthenticatorOperation() async {
    await authenticatorCancel();
  }

  @override
  Future<void> goToSettings() {
    throw UnimplementedError();
  }

  @override
  Future<AuthenticateResponseType> getSavedCredential(AuthenticateRequestType request) {
    // TODO: implement getSavedCredential
    throw UnimplementedError();
  }
}
