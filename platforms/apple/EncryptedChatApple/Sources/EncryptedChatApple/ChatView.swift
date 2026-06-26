import SwiftUI

public struct ChatView: View {
    @EnvironmentObject private var model: ChatAppModel
    @State private var draft = ""

    public init() {}

    public var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                verificationBanner
                List(model.messages) { message in
                    MessageRow(message: message)
                        .listRowSeparator(.hidden)
                }
                .listStyle(.plain)
                composer
            }
            .navigationTitle("Encrypted Chat")
        }
    }

    private var verificationBanner: some View {
        HStack {
            Image(systemName: model.verificationState == .trusted ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
            Text(model.verificationState == .trusted ? "Peer identity verified" : "Peer identity not verified")
            Spacer()
            Text(model.verificationState.rawValue)
                .font(.caption)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(.thinMaterial, in: Capsule())
        }
        .font(.subheadline)
        .padding()
        .foregroundStyle(model.verificationState == .trusted ? .green : .orange)
    }

    private var composer: some View {
        HStack {
            TextField("Message", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
            Button {
                model.send(draft)
                draft = ""
            } label: {
                Image(systemName: "paperplane.fill")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!model.canSend || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding()
    }
}

private struct MessageRow: View {
    let message: ChatMessage

    var body: some View {
        HStack {
            if message.direction == .outbound { Spacer(minLength: 40) }
            VStack(alignment: .leading, spacing: 6) {
                Text(message.body)
                Text(message.isVerified ? "Verified" : "Unverified")
                    .font(.caption2)
                    .foregroundStyle(message.isVerified ? .green : .orange)
            }
            .padding(10)
            .background(message.direction == .outbound ? Color.accentColor.opacity(0.18) : Color.secondary.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            if message.direction == .inbound { Spacer(minLength: 40) }
        }
    }
}
