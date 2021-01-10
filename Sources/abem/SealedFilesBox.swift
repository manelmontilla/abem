//
//  File.swift
//  
//
//  Created by Manel Montilla on 9/1/21.
//

import Foundation
import Sodium
extension Abem {
    
    class SealedFilesBox {
        
        public let file: URL
        let header: SealedFilesBoxHeader
        let box: SealedFilesBoxData
        let filesTable: SealedFilesBoxFilesData
        var fileHandle: FileHandle
        var sk: Bytes
        var fk: Bytes
        var dk: Bytes
        
        
        deinit {
            let sodium = Sodium()
            sodium.utils.zero(&self.fk)
            sodium.utils.zero(&self.dk)
            sodium.utils.zero(&self.sk)
        }
        
        
        
        init?(from file:URL, with password: String) throws {
            
            guard file.startAccessingSecurityScopedResource() else {throw
                Abem.SealedFilesBoxError.LogicalError("can not access file: \(file.absoluteString)")
            }
            defer {file.stopAccessingSecurityScopedResource()}
            
            self.file = file
            
            // Open the handler for reading.
            self.fileHandle = try FileHandle(forReadingFrom: file)
            
            // Read the header.
            let header = try SealedFilesBoxHeader(from: self.fileHandle)!
            var mk = masterKey(from: password, salt: header.salt)
            
            // Derive the SealedBoxData key.
            let sodium = Sodium()
            var sk = sodium.keyDerivation.derive(secretKey: mk, index: 1, length: sodium.secretBox.KeyBytes , context: "SealedBoxData")!
            var dk = sodium.keyDerivation.derive(secretKey: mk, index: 2, length: sodium.secretBox.KeyBytes , context: "Directories")!
            var fk = sodium.keyDerivation.derive(secretKey: mk, index: 3, length: sodium.secretBox.KeyBytes , context: "Directories")!
            sodium.utils.zero(&mk)
            
            self.box = try SealedFilesBoxData(from: self.fileHandle, key: mk, size: header.sealedBoxDataSize)!

            self.filesTable = try SealedFilesBoxFilesData(from: self.fileHandle, key: dk, size: self.box.directoriesSize)!
            
        }
        
        
    }
    
    
    public enum SealedFilesBoxError: Error {
        case LogicalError(_ Description: String)
    }
    
    
    struct SealedFilesBoxHeader {
        let salt: Data
        let sealedBoxDataSize: Int64
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
                $0.load(as: Int64.self)
            }
        }
        
    }
    
}

extension SealedFilesBoxData {
    
    init?(from: FileHandle, key: Bytes, size: Int64) throws {
        guard #available(OSX 10.15.4, *) else {throw Abem.AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw Abem.AbemError.operationNotSupported}
        // Decrypt using the derived key.
        let ciphertext = try from.read(upToCount: Int(size))!
        let sodium = Sodium()
        let contentBytes  = sodium.secretBox.open(nonceAndAuthenticatedCipherText: [UInt8](ciphertext), secretKey: key)
        guard let content = contentBytes else {  throw Abem.SealedFilesBoxError.LogicalError("invalid sealed file") }
        
        self = try SealedFilesBoxData(serializedData:Data(content))
        
    }
}

extension SealedFilesBoxFilesData {

    init?(from: FileHandle, key: Bytes, size: Int64) throws {
        guard #available(OSX 10.15.4, *) else {throw Abem.AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw Abem.AbemError.operationNotSupported}
        // Decrypt using the derived key.
        let ciphertext = try from.read(upToCount: Int(size))!
        let sodium = Sodium()
        let contentBytes  = sodium.secretBox.open(nonceAndAuthenticatedCipherText: [UInt8](ciphertext), secretKey: key)
        guard let content = contentBytes else {  throw Abem.SealedFilesBoxError.LogicalError("invalid sealed file") }
        self = try SealedFilesBoxFilesData(serializedData:Data(content))
        
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
