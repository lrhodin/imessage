import SwiftUI

/// SF Symbols require macOS 11+. On 10.15, fall back to a text label.
struct SymbolOrText: View {
    let systemName: String
    let fallback: String

    var body: some View {
        if #available(macOS 11.0, *) {
            Image(systemName: systemName)
        } else {
            Text(fallback)
        }
    }
}
