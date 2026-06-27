import SwiftUI

public struct RootView: View {
    public init() {}

    public var body: some View {
        TabView {
            ChatView()
                .tabItem { Label("Chat", systemImage: "message") }
            IdentityView()
                .tabItem { Label("Identity", systemImage: "person.badge.key") }
            TransportView()
                .tabItem { Label("Transport", systemImage: "network") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
    }
}
