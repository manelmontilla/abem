//
//  File.swift
//  
//
//  Created by Manel Montilla on 10/1/21.
//


import XCTest
import Sodium
import Foundation
@testable import abem

final class SealedFileBoxTest: XCTestCase {
    func testSealedFilesBoxCreate() throws {
        let password = "aB<z0aT!_Q"
        let data = try abem.Abem.SealedFilesBox.create(named: "test", with: password)
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("sealed_box_test.sealed")
        defer {
            try! FileManager.default.removeItem(at: temp)
        }
        try data.write(to: temp)
        
        _ = try abem.Abem.SealedFilesBox(from: temp, with: password)
    }
    
    
    
    static var allTests = [
        ("testSealedFilesBoxCreate", testSealedFilesBoxCreate),
    ]
}

