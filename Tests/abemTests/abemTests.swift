import XCTest
import Sodium
import Foundation
@testable import abem

final class abemTests: XCTestCase {
    func testEncrypt() throws {
        let data = "Hello world".data(using: .utf8)!
        let ciphertext = try Abem.Encrypt(data: data, metadata:"", with: "aB<z0aT!_Q")
        let payload = try Abem.Decrypt(ciphertext!, with: "aB<z0aT!_Q")
        XCTAssertEqual(String(data: payload.payload, encoding: .utf8), "Hello world")
    }
    
    func testEncryptWithMetadata() throws {
        let data = "Hello world".data(using: .utf8)!
        var metadata = "metadata"
        var ciphertext = try Abem.Encrypt(data: data, metadata:metadata, with: "aB<z0aT!_Q")
        var payload = try Abem.Decrypt(ciphertext!, with: "aB<z0aT!_Q")
        XCTAssertEqual(String(data: payload.payload, encoding: .utf8), "Hello world")
        XCTAssertEqual(payload.metadata, metadata)
        
        metadata = ""
        ciphertext = try Abem.Encrypt(data: data, metadata:metadata, with: "aB<z0aT!_Q")
        payload = try Abem.Decrypt(ciphertext!, with: "aB<z0aT!_Q")
        XCTAssertEqual(String(data: payload.payload, encoding: .utf8), "Hello world")
        XCTAssertEqual(payload.metadata, metadata)
        
        
        // Test it encrypts properly metadata with 255 chars.
        metadata = String((0..<255).flatMap{
            _ in
            return "a"
        })
        
        ciphertext = try Abem.Encrypt(data: data, metadata:metadata, with: "aB<z0aT!_Q")
        payload = try Abem.Decrypt(ciphertext!, with: "aB<z0aT!_Q")
        XCTAssertEqual(String(data: payload.payload, encoding: .utf8), "Hello world")
        XCTAssertEqual(payload.metadata, metadata)
        
        
        // Test it trims the metadata to 255 chars if it is longer than 255 chars.
        metadata = String((0..<255).flatMap{
            _ in
            return "a"
        })
        
        
        ciphertext = try Abem.Encrypt(data: data, metadata:metadata+"b", with: "aB<z0aT!_Q")
        payload = try Abem.Decrypt(ciphertext!, with: "aB<z0aT!_Q")
        XCTAssertEqual(String(data: payload.payload, encoding: .utf8), "Hello world")
        XCTAssertEqual(payload.metadata, metadata)
        
        
    }
    
    func testPassowrdStrength() {
        XCTAssertEqual(Abem.PasswordStrength.Check("abcdef"),.weak)
        XCTAssertEqual(Abem.PasswordStrength.Check("aB<z0aT!"),.strong)
        XCTAssertEqual(Abem.PasswordStrength.Check("@"),.weak)
        XCTAssertEqual(Abem.PasswordStrength.Check("aB<z0aT!_Q"),.strong)
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
    
    func testPasswordEntropy() {
        var entropy = Abem.PasswordStrength.Entropy(for: "example")
        XCTAssertEqual(entropy.truncate(),32.90)
        entropy = Abem.PasswordStrength.Entropy(for: "entraña")
        XCTAssertEqual(entropy.truncate(),52.88)
    }
    
    static var allTests = [
        ("testEncrypt", testEncrypt),
        ("testPassowrdStrength", testPassowrdStrength),
        ("testCiphertextCombined",testCiphertextCombined),
        ("testPasswordEntropy",testPasswordEntropy)
        
    ]
}

extension Double {
    func truncate() -> Double{
        ((self*100).rounded())/100
    }
}
