import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(magic_swiftTests.allTests),
    ]
}
#endif
