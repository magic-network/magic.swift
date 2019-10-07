import Foundation
import XCTest
@testable import Magic

final class MagicTests: XCTestCase {
    func testAccount() {
        XCTAssertNotNil(Magic.Account.shared.getUsername())
    }
}
