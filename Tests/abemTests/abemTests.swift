import XCTest
import Sodium
import Foundation
@testable import abem

final class abemTests: XCTestCase {
    func testEncrypt() throws {
        let data = "Hello world".data(using: .utf8)!
        let cyphertext = try Abem.Encrypt(data: data, metadata:"", with: "aB<z0aT!_Q")
        let payload = try Abem.Decrypt(cyphertext!, with: "aB<z0aT!_Q")
        XCTAssertEqual(String(data: payload.payload, encoding: .utf8), "Hello world")
    }
    
    func testEncryptWithMetadata() throws {
        let data = "Hello world".data(using: .utf8)!
        let metadata = "metadata"
        let cyphertext = try Abem.Encrypt(data: data, metadata:metadata, with: "aB<z0aT!_Q")
        let payload = try Abem.Decrypt(cyphertext!, with: "aB<z0aT!_Q")
        XCTAssertEqual(String(data: payload.payload, encoding: .utf8), "Hello world")
        XCTAssertEqual(payload.metadata, metadata)
    }
    
    func testPassowrdStrength() {
        XCTAssertEqual(PasswordStrength.Check("abcdef"),.weak)
        XCTAssertEqual(PasswordStrength.Check("aB<z0aT!"),.strong)
        XCTAssertEqual(PasswordStrength.Check("@"),.weak)
        XCTAssertEqual(PasswordStrength.Check("aB<z0aT!_Q"),.strong)
    }
    
    func testCiphertextCombined() {
        let ci = "ciphertext".data(using: .utf8)!
        var rawSalt = ""
        for _ in 0..<Sodium().pwHash.SaltBytes {
            rawSalt.append("a")
        }
        let salt = rawSalt.data(using: .utf8)!
        let ciphertext = Abem.Ciphertext(ci,salt)
        let raw = ciphertext.Combined()
        let ciphertext2 = Abem.Ciphertext(from: raw)
        XCTAssertEqual(ciphertext2.salt,ciphertext2.salt)
        XCTAssertEqual(ciphertext2.ciphertext,ciphertext.ciphertext)
        
    }
    
    static var allTests = [
        ("testEncrypt", testEncrypt),
        ("testPassowrdStrength", testPassowrdStrength),
        ("testCiphertextCombined",testCiphertextCombined)
        
    ]
}
