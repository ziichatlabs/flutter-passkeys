// Autogenerated from Pigeon (v11.0.1), do not edit directly.
// See also: https://pub.dev/packages/pigeon

import Foundation
#if os(iOS)
import Flutter
#elseif os(macOS)
import FlutterMacOS
#else
#error("Unsupported platform.")
#endif

private func isNullish(_ value: Any?) -> Bool {
  return value is NSNull || value == nil
}

private func wrapResult(_ result: Any?) -> [Any?] {
  return [result]
}

private func wrapError(_ error: Any) -> [Any?] {
  if let flutterError = error as? FlutterError {
    return [
      flutterError.code,
      flutterError.message,
      flutterError.details
    ]
  }
  return [
    "\(error)",
    "\(type(of: error))",
    "Stacktrace: \(Thread.callStackSymbols)"
  ]
}

private func nilOrValue<T>(_ value: Any?) -> T? {
  if value is NSNull { return nil }
  return value as! T?
}

/// Represents a relying party
///
/// Generated class from Pigeon that represents data sent in messages.
struct RelyingParty {
  /// Name of the relying party
  var name: String
  /// ID of the relying party
  var id: String

  static func fromList(_ list: [Any?]) -> RelyingParty? {
    let name = list[0] as! String
    let id = list[1] as! String

    return RelyingParty(
      name: name,
      id: id
    )
  }
  func toList() -> [Any?] {
    return [
      name,
      id,
    ]
  }
}

/// Represents a user
///
/// Generated class from Pigeon that represents data sent in messages.
struct User {
  /// The name
  var name: String
  /// The ID
  var id: String

  static func fromList(_ list: [Any?]) -> User? {
    let name = list[0] as! String
    let id = list[1] as! String

    return User(
      name: name,
      id: id
    )
  }
  func toList() -> [Any?] {
    return [
      name,
      id,
    ]
  }
}

/// Represents a register response
///
/// Generated class from Pigeon that represents data sent in messages.
struct RegisterResponse {
  /// The ID
  var id: String
  /// The raw ID
  var rawId: String
  /// The client data JSON
  var clientDataJSON: String
  /// The attestation object
  var attestationObject: String

  static func fromList(_ list: [Any?]) -> RegisterResponse? {
    let id = list[0] as! String
    let rawId = list[1] as! String
    let clientDataJSON = list[2] as! String
    let attestationObject = list[3] as! String

    return RegisterResponse(
      id: id,
      rawId: rawId,
      clientDataJSON: clientDataJSON,
      attestationObject: attestationObject
    )
  }
  func toList() -> [Any?] {
    return [
      id,
      rawId,
      clientDataJSON,
      attestationObject,
    ]
  }
}

/// Represents an authenticate response
///
/// Generated class from Pigeon that represents data sent in messages.
struct AuthenticateResponse {
  /// The ID
  var id: String
  /// The raw ID
  var rawId: String
  /// The client data JSON
  var clientDataJSON: String
  /// The authenticator data
  var authenticatorData: String
  /// Signed challenge
  var signature: String
  var userHandle: String

  static func fromList(_ list: [Any?]) -> AuthenticateResponse? {
    let id = list[0] as! String
    let rawId = list[1] as! String
    let clientDataJSON = list[2] as! String
    let authenticatorData = list[3] as! String
    let signature = list[4] as! String
    let userHandle = list[5] as! String

    return AuthenticateResponse(
      id: id,
      rawId: rawId,
      clientDataJSON: clientDataJSON,
      authenticatorData: authenticatorData,
      signature: signature,
      userHandle: userHandle
    )
  }
  func toList() -> [Any?] {
    return [
      id,
      rawId,
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    ]
  }
}

private class PasskeysApiCodecReader: FlutterStandardReader {
  override func readValue(ofType type: UInt8) -> Any? {
    switch type {
      case 128:
        return AuthenticateResponse.fromList(self.readValue() as! [Any?])
      case 129:
        return RegisterResponse.fromList(self.readValue() as! [Any?])
      case 130:
        return RelyingParty.fromList(self.readValue() as! [Any?])
      case 131:
        return User.fromList(self.readValue() as! [Any?])
      default:
        return super.readValue(ofType: type)
    }
  }
}

private class PasskeysApiCodecWriter: FlutterStandardWriter {
  override func writeValue(_ value: Any) {
    if let value = value as? AuthenticateResponse {
      super.writeByte(128)
      super.writeValue(value.toList())
    } else if let value = value as? RegisterResponse {
      super.writeByte(129)
      super.writeValue(value.toList())
    } else if let value = value as? RelyingParty {
      super.writeByte(130)
      super.writeValue(value.toList())
    } else if let value = value as? User {
      super.writeByte(131)
      super.writeValue(value.toList())
    } else {
      super.writeValue(value)
    }
  }
}

private class PasskeysApiCodecReaderWriter: FlutterStandardReaderWriter {
  override func reader(with data: Data) -> FlutterStandardReader {
    return PasskeysApiCodecReader(data: data)
  }

  override func writer(with data: NSMutableData) -> FlutterStandardWriter {
    return PasskeysApiCodecWriter(data: data)
  }
}

class PasskeysApiCodec: FlutterStandardMessageCodec {
  static let shared = PasskeysApiCodec(readerWriter: PasskeysApiCodecReaderWriter())
}

/// Generated protocol from Pigeon that represents a handler of messages from Flutter.
protocol PasskeysApi {
  func canAuthenticate() throws -> Bool
  func register(challenge: String, relyingParty: RelyingParty, user: User, excludeCredentialIDs: [String], completion: @escaping (Result<RegisterResponse, Error>) -> Void)
  func authenticate(relyingPartyId: String, challenge: String, conditionalUI: Bool, allowedCredentialIDs: [String], completion: @escaping (Result<AuthenticateResponse, Error>) -> Void)
  func cancelCurrentAuthenticatorOperation(completion: @escaping (Result<Void, Error>) -> Void)
  func goToSettings(completion: @escaping (Result<Void, Error>) -> Void)
  func getSavedCredential(relyingPartyId: String, challenge: String, timeout: Int64?, userVerification: String?, completion: @escaping (Result<AuthenticateResponse, Error>) -> Void)
}

/// Generated setup class from Pigeon to handle messages through the `binaryMessenger`.
class PasskeysApiSetup {
  /// The codec used by PasskeysApi.
  static var codec: FlutterStandardMessageCodec { PasskeysApiCodec.shared }
  /// Sets up an instance of `PasskeysApi` to handle messages through the `binaryMessenger`.
  static func setUp(binaryMessenger: FlutterBinaryMessenger, api: PasskeysApi?) {
    let canAuthenticateChannel = FlutterBasicMessageChannel(name: "dev.flutter.pigeon.passkeys_ios.PasskeysApi.canAuthenticate", binaryMessenger: binaryMessenger, codec: codec)
    if let api = api {
      canAuthenticateChannel.setMessageHandler { _, reply in
        do {
          let result = try api.canAuthenticate()
          reply(wrapResult(result))
        } catch {
          reply(wrapError(error))
        }
      }
    } else {
      canAuthenticateChannel.setMessageHandler(nil)
    }
    let registerChannel = FlutterBasicMessageChannel(name: "dev.flutter.pigeon.passkeys_ios.PasskeysApi.register", binaryMessenger: binaryMessenger, codec: codec)
    if let api = api {
      registerChannel.setMessageHandler { message, reply in
        let args = message as! [Any?]
        let challengeArg = args[0] as! String
        let relyingPartyArg = args[1] as! RelyingParty
        let userArg = args[2] as! User
        let excludeCredentialIDsArg = args[3] as! [String]
        api.register(challenge: challengeArg, relyingParty: relyingPartyArg, user: userArg, excludeCredentialIDs: excludeCredentialIDsArg) { result in
          switch result {
            case .success(let res):
              reply(wrapResult(res))
            case .failure(let error):
              reply(wrapError(error))
          }
        }
      }
    } else {
      registerChannel.setMessageHandler(nil)
    }
    let authenticateChannel = FlutterBasicMessageChannel(name: "dev.flutter.pigeon.passkeys_ios.PasskeysApi.authenticate", binaryMessenger: binaryMessenger, codec: codec)
    if let api = api {
      authenticateChannel.setMessageHandler { message, reply in
        let args = message as! [Any?]
        let relyingPartyIdArg = args[0] as! String
        let challengeArg = args[1] as! String
        let conditionalUIArg = args[2] as! Bool
        let allowedCredentialIDsArg = args[3] as! [String]
        api.authenticate(relyingPartyId: relyingPartyIdArg, challenge: challengeArg, conditionalUI: conditionalUIArg, allowedCredentialIDs: allowedCredentialIDsArg) { result in
          switch result {
            case .success(let res):
              reply(wrapResult(res))
            case .failure(let error):
              reply(wrapError(error))
          }
        }
      }
    } else {
      authenticateChannel.setMessageHandler(nil)
    }
    let cancelCurrentAuthenticatorOperationChannel = FlutterBasicMessageChannel(name: "dev.flutter.pigeon.passkeys_ios.PasskeysApi.cancelCurrentAuthenticatorOperation", binaryMessenger: binaryMessenger, codec: codec)
    if let api = api {
      cancelCurrentAuthenticatorOperationChannel.setMessageHandler { _, reply in
        api.cancelCurrentAuthenticatorOperation() { result in
          switch result {
            case .success:
              reply(wrapResult(nil))
            case .failure(let error):
              reply(wrapError(error))
          }
        }
      }
    } else {
      cancelCurrentAuthenticatorOperationChannel.setMessageHandler(nil)
    }
    let goToSettingsChannel = FlutterBasicMessageChannel(name: "dev.flutter.pigeon.passkeys_ios.PasskeysApi.goToSettings", binaryMessenger: binaryMessenger, codec: codec)
    if let api = api {
      goToSettingsChannel.setMessageHandler { _, reply in
        api.goToSettings() { result in
          switch result {
            case .success:
              reply(wrapResult(nil))
            case .failure(let error):
              reply(wrapError(error))
          }
        }
      }
    } else {
      goToSettingsChannel.setMessageHandler(nil)
    }
    let getSavedCredentialChannel = FlutterBasicMessageChannel(name: "dev.flutter.pigeon.passkeys_ios.PasskeysApi.getSavedCredential", binaryMessenger: binaryMessenger, codec: codec)
    if let api = api {
      getSavedCredentialChannel.setMessageHandler { message, reply in
        let args = message as! [Any?]
        let relyingPartyIdArg = args[0] as! String
        let challengeArg = args[1] as! String
        let timeoutArg: Int64? = isNullish(args[2]) ? nil : (args[2] is Int64? ? args[2] as! Int64? : Int64(args[2] as! Int32))
        let userVerificationArg: String? = nilOrValue(args[3])
        api.getSavedCredential(relyingPartyId: relyingPartyIdArg, challenge: challengeArg, timeout: timeoutArg, userVerification: userVerificationArg) { result in
          switch result {
            case .success(let res):
              reply(wrapResult(res))
            case .failure(let error):
              reply(wrapError(error))
          }
        }
      }
    } else {
      getSavedCredentialChannel.setMessageHandler(nil)
    }
  }
}
