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
    
    func testSealedFilesBoxAddFile() throws {
        let password = "aB<z0aT!_Q"
        
        let data = try abem.Abem.SealedFilesBox.create(named: "test", with: password)
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("sealed_box_test.sealed")
        defer {
            try! FileManager.default.removeItem(at: temp)
        }
        try data.write(to: temp)
        print(temp.absoluteString)
        var box = try abem.Abem.SealedFilesBox(from: temp, with: password)!
        let dir = try box.rootDir.get()
        let testContent = "test".data(using: .utf8)!
        _ = try! box.addFile(in: dir, named: "File1", containing: testContent)
        box = try abem.Abem.SealedFilesBox(from: temp, with: password)!
        let root = try! box.rootDir.get()
        let infos = try! root.Stat()
        XCTAssertEqual(infos.count, 1)
        let info = infos[0]
        guard case .File(let file) = info else {
            XCTFail("invalid fileInfo")
            return
        }
        XCTAssertEqual(file.fullName.absoluteString,"/File1")
    }
    
    func testTree() throws {
        var t = Tree(root:Node(name:""))
        var n = Node(name:"first")
        try t.addNode(URL(string:"/")!, n)
        XCTAssertEqual(t.root.children[0].name, n.name)
        n = Node(name:"second")
        try t.addNode(URL(string:"/first")!, n)
        print(t.root.children[0].children.count)
        XCTAssertEqual(t.root.children[0].children[0].name, n.name)
    
    }
    
    static var allTests = [
        ("testSealedFilesBoxCreate", testSealedFilesBoxCreate),
    ]
}

