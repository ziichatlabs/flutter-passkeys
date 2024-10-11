import AuthenticationServices
import Flutter
import Foundation

@available(iOS 16.0, *)
class PasskeyCredentialController: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    public var completion: ((Result<AuthenticateResponse, Error>) -> Void)?

    init(completion: @escaping ((Result<AuthenticateResponse, Error>) -> Void)) {
        self.completion = completion
    }

    func getSavedCredential(relyingPartyId: String, challenge: String, userVerification: String?, completion: @escaping (Result<AuthenticateResponse, Error>) -> Void) {
        guard let decodedChallenge = Data.fromBase64Url(challenge) else {
            completion(.failure(CustomErrors.decodingChallenge))
            return
        }

        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingPartyId)
        let request = platformProvider.createCredentialAssertionRequest(challenge: decodedChallenge)
        request.allowedCredentials = []

        if let userVerification = userVerification {
            switch userVerification {
            case "preferred":
                request.userVerificationPreference = .preferred
            case "required":
                request.userVerificationPreference = .required
            case "discouraged":
                request.userVerificationPreference = .discouraged
            default:
                break
            }
        }

        let authorizationController = ASAuthorizationController(authorizationRequests: [request])
        authorizationController.delegate = self
        authorizationController.presentationContextProvider = self
        authorizationController.performRequests(options: .preferImmediatelyAvailableCredentials)
    }

    // MARK: - ASAuthorizationControllerDelegate
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let r as ASAuthorizationPublicKeyCredentialAssertion:
            let response = AuthenticateResponse(
                id: r.credentialID.toBase64URL(),
                rawId: r.credentialID.toBase64URL(),
                clientDataJSON: r.rawClientDataJSON.toBase64URL(),
                authenticatorData: r.rawAuthenticatorData.toBase64URL(),
                signature: r.signature.toBase64URL(),
                userHandle: r.userID.toBase64URL()
            )
            completion?(.success(response))
        default:
            completion?(.failure(CustomErrors.unexpectedAuthorizationResponse))
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        if let err = error as? ASAuthorizationError {
            completion?(.failure(FlutterError(from: err)))
        } else {
            completion?(.failure(CustomErrors.unknown))
        }
    }

    // MARK: - ASAuthorizationControllerPresentationContextProviding

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        let delegate = UIApplication.shared.delegate

        if let flutterDelegate = delegate as? FlutterAppDelegate {
            return flutterDelegate.window
        }

        return (delegate?.window!!)!
    }

}
