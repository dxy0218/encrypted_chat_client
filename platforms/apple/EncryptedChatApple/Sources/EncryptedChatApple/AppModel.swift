import Foundation
import Combine

public struct ChatMessage: Identifiable, Equatable {
    public enum Direction {
        case inbound
        case outbound
    }

    public let id = UUID()
    public let direction: Direction
    public let body: String
    public let isVerified: Bool
    public let timestamp: Date
}

public enum VerificationState: String {
    case unverified = "Unverified"
    case limited = "Limited"
    case trusted = "Trusted"
    case rejected = "Rejected"
}

@MainActor
public final class ChatAppModel: ObservableObject {
    @Published public var relayHost = "127.0.0.1"
    @Published public var relayPort = "65432"
    @Published public var alias = "default"
    @Published public var status = "Disconnected"
    @Published public var verificationState: VerificationState = .unverified
    @Published public var peerFingerprint = "No peer connected"
    @Published public var safetyPhrase = "Waiting for handshake"
    @Published public private(set) var unverifiedMessagesRemaining = 5
    @Published public var messages: [ChatMessage] = []

    public init() {}

    public var canSend: Bool {
        verificationState == .trusted || unverifiedMessagesRemaining > 0
    }

    public func connect() async {
        status = "Connecting"
        try? await Task.sleep(for: .milliseconds(250))
        status = "Ready for handshake"
        peerFingerprint = "Pending peer identity"
        safetyPhrase = "Compare phrase after HELLO3"
        verificationState = .limited
    }

    public func trustPeer() {
        verificationState = .trusted
        unverifiedMessagesRemaining = 5
    }

    public func rejectPeer() {
        verificationState = .rejected
        unverifiedMessagesRemaining = 0
    }

    public func resetPeer() {
        verificationState = .unverified
        peerFingerprint = "No peer connected"
        safetyPhrase = "Waiting for handshake"
        unverifiedMessagesRemaining = 5
    }

    public func send(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, canSend else { return }
        let verified = verificationState == .trusted
        if !verified {
            unverifiedMessagesRemaining = max(0, unverifiedMessagesRemaining - 1)
        }
        let warning = verified ? "" : "[Unverified identity: authenticity may be uncertain] "
        messages.append(ChatMessage(direction: .outbound, body: warning + trimmed, isVerified: verified, timestamp: Date()))
    }
}
