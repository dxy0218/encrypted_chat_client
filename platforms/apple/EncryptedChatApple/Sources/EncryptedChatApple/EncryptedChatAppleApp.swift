import SwiftUI

public struct EncryptedChatAppleApp: App {
    @StateObject private var model = ChatAppModel()

    public init() {}

    public var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
    }
}
