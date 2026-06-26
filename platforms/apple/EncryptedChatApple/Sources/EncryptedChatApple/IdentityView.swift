import SwiftUI

public struct IdentityView: View {
    @EnvironmentObject private var model: ChatAppModel

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                Section("Peer") {
                    LabeledContent("Fingerprint", value: model.peerFingerprint)
                    LabeledContent("Safety phrase", value: model.safetyPhrase)
                    LabeledContent("State", value: model.verificationState.rawValue)
                    LabeledContent("Unverified sends left", value: "\(model.unverifiedMessagesRemaining)")
                }
                Section {
                    Button("Trust peer") { model.trustPeer() }
                    Button("Reject peer", role: .destructive) { model.rejectPeer() }
                    Button("Reset peer") { model.resetPeer() }
                }
            }
            .navigationTitle("Identity")
        }
    }
}
