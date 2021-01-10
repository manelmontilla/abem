//
//  File.swift
//  
//
//  Created by Manel Montilla on 9/1/21.
//

import Foundation
import Sodium
extension Abem {
    
    typealias  filesIndex =  [[UInt8]:Int]
    
    class SealedFilesBox {
        
        public let file: URL
        let header: SealedFilesBoxHeader
        let box: SealedFilesBox_BoxData
        let filesTable: ExtendedFilesData
        var sk: Bytes?
        var fk: Bytes?
        var dk: Bytes?
        
        
        deinit {
            let sodium = Sodium()
            if self.fk != nil {
               sodium.utils.zero(&self.fk!)
            }
            if self.dk != nil {
              sodium.utils.zero(&self.dk!)
            }
            if self.sk != nil {
             sodium.utils.zero(&self.sk!)
            }
        }
        
        
        
        init?(from file:URL, with password: String) throws {
            
            guard file.startAccessingSecurityScopedResource() else {throw
                Abem.SealedFilesBoxError.LogicalError("can not access file: \(file.absoluteString)")
            }
            defer {file.stopAccessingSecurityScopedResource()}
            
            self.file = file
            
            // Open the handler for reading.
            let fileHandle = try FileHandle(forReadingFrom: file)
            
            let sodium = Sodium()
            // Read the header.
            self.header = try SealedFilesBoxHeader(from: fileHandle)!
            
            // Derive the keys.
            var mk = masterKey(from: password, salt: header.salt)
            self.sk = sodium.keyDerivation.derive(secretKey: mk, index: 1, length: sodium.secretBox.KeyBytes , context: "SealedBoxData")!
            self.dk = sodium.keyDerivation.derive(secretKey: mk, index: 2, length: sodium.secretBox.KeyBytes , context: "FilesData")!
            self.fk = sodium.keyDerivation.derive(secretKey: mk, index: 3, length: sodium.secretBox.KeyBytes , context: "Files")!
            sodium.utils.zero(&mk)
            
            
            // Read the box data.
            self.box = try SealedFilesBox_BoxData(from: fileHandle, key: mk, size: self.header.sealedBoxDataSize)!

            // Read the files box data.
            let filesTableData = try SealedFilesBox_FilesData(from: fileHandle, key: self.dk!, size: self.box.filesDataSize)!
            self.filesTable = ExtendedFilesData(filesTableData)
            
            
        }
        
        
        
        
    }
    
    struct SealedFilesBoxHeader {
        let salt: Data
        let sealedBoxDataSize: UInt64
        init?(from file: FileHandle) throws {
            guard #available(OSX 10.15.4, *) else {throw AbemError.operationNotSupported}
            guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
            let sodium = Sodium()
            
            // Read the salt.
            self.salt = try file.read(upToCount:sodium.pwHash.SaltBytes)!
            
            // Read the size of the sealed box data.
            let lenData = try file.read(upToCount: 8)!
            if lenData.count != 4 {
                throw Abem.SealedFilesBoxError.LogicalError("invalid sealed file")
            }
            
            self.sealedBoxDataSize = lenData.withUnsafeBytes{
                $0.load(as: UInt64.self)
            }
        }
        
    }
    
    public enum SealedFilesBoxError: Error {
        case LogicalError(_ Description: String)
    }
    
    struct ExtendedFilesData {
        
        let basicData: SealedFilesBox_FilesData
        let index: filesIndex
        init(_ data: SealedFilesBox_FilesData) {
            self.basicData = data
            self.index = data.buildIndex()
        }
    }
    
}

extension SealedFilesBox_BoxData {
    
    init?(from: FileHandle, key: Bytes, size: UInt64) throws {
        guard #available(OSX 10.15.4, *) else {throw Abem.AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw Abem.AbemError.operationNotSupported}
        // Decrypt using the derived key.
        let ciphertext = try from.read(upToCount: Int(size))!
        let sodium = Sodium()
        let contentBytes  = sodium.secretBox.open(nonceAndAuthenticatedCipherText: [UInt8](ciphertext), secretKey: key)
        guard let content = contentBytes else {  throw Abem.SealedFilesBoxError.LogicalError("invalid sealed file") }
        
        self = try SealedFilesBox_BoxData(serializedData:Data(content))
        
    }
}

extension SealedFilesBox_FilesData {

    init?(from: FileHandle, key: Bytes, size: UInt64) throws {
        guard #available(OSX 10.15.4, *) else {throw Abem.AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw Abem.AbemError.operationNotSupported}
        // Decrypt using the derived key.
        let ciphertext = try from.read(upToCount: Int(size))!
        let sodium = Sodium()
        let contentBytes  = sodium.secretBox.open(nonceAndAuthenticatedCipherText: [UInt8](ciphertext), secretKey: key)
        guard let content = contentBytes else {  throw Abem.SealedFilesBoxError.LogicalError("invalid sealed file") }
        self = try SealedFilesBox_FilesData(serializedData:Data(content))
        
    }
    
    func buildIndex() ->  Abem.filesIndex {
        var index = Abem.filesIndex()
        for (i , file) in self.fileList.enumerated() {
            let h = [UInt8](file.hash)
            index[h] = i
        }
        return index
    }
    
}


func masterKey(from password: String, salt: Data) -> [UInt8] {
    let sodium = Sodium()
    // Derive the encryption key from the password.
    let pwdBytes = password.bytes
    let keySize = sodium.secretBox.KeyBytes
    let key = sodium.pwHash.hash(outputLength: keySize, passwd: pwdBytes, salt: [UInt8](salt), opsLimit: sodium.pwHash.OpsLimitModerate, memLimit: sodium.pwHash.MemLimitModerate)!
    return key
}
