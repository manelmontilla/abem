import XCTest
@testable import abem

final class abemTests: XCTestCase {
    func testEncrypt() throws {
        let data = "Hello world".data(using: .utf8)!
        let cyphertext = try Abem.Encrypt(data: data, with: "super secret")
        let cleartext = try Abem.Decrypt(cyphertext!, with: "super secret")
        XCTAssertEqual(String(data: cleartext, encoding: .utf8), "Hello world")
    }
    
    func testPassowrdStrength(){
        XCTAssertEqual(PasswordStrength.Check("abcdef"),.weak)
        XCTAssertEqual(PasswordStrength.Check("aB<z0aT!"),.weak)
        XCTAssertEqual(PasswordStrength.Check("aB<z0aT!_Q"),.strong)
    }

    static var allTests = [
        ("testEncrypt", testEncrypt)
    ]
}

class MockFileManager: FileManager {
    var data: Data?
    init(using content: Data?) {
        self.data = content
    }
    override func contents(atPath path: String) -> Data? {
        return data
    }
}
