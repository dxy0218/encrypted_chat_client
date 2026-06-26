import SwiftUI

public struct SettingsView: View {
    @EnvironmentObject private var model: ChatAppModel
    @State private var padPayloads = true
    @State private var storeOfflinePackets = true

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                Section("Profile") {
                    TextField("Alias", text: $model.alias)
                        .textInputAutocapitalization(.never)
                }
                Section("Privacy") {
                    Toggle("Pad encrypted payloads", isOn: $padPayloads)
                    Toggle("Enable offline packet fetch", isOn: $storeOfflinePackets)
                }
                Section("Version") {
                    LabeledContent("Build", value: "v0.01beta")
                }
            }
            .navigationTitle("Settings")
        }
    }
}
