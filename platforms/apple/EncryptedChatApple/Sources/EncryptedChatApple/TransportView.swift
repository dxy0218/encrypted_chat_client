import SwiftUI

public struct TransportView: View {
    @EnvironmentObject private var model: ChatAppModel

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                Section("Relay") {
                    TextField("Host", text: $model.relayHost)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Port", text: $model.relayPort)
                        .keyboardType(.numberPad)
                    LabeledContent("Status", value: model.status)
                }
                Section {
                    Button("Connect") {
                        Task { await model.connect() }
                    }
                    Button("Discover LAN relay") {
                        model.status = "LAN discovery queued"
                    }
                }
            }
            .navigationTitle("Transport")
        }
    }
}
