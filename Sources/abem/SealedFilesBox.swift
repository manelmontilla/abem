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
    
    public class SealedFilesBox {
        
        static let filesDataAreaMaxSize = 2 * (2 << 19) // 2 MB's.
        
        public let file: URL
        
        var header: SealedFilesBoxHeader?
        var filesTable: ExtendedFilesData?
        var fk: Bytes?
        var dk: Bytes?
        
        public var rootDir: Result<SealedFilesBoxDirectory,Error> {
            get {
                guard let table = self.filesTable else {
                    return Result{
                        throw SealedFilesBoxError.BoxClosed
                    }
                }
                let r = table.basicData.rootDir
                let directoryInfo = SealedFilesBoxDirectory(directoryData: r, box: self)
                return Result{
                    directoryInfo
                }
            }
        }
        
        deinit {
            let sodium = Sodium()
            if self.fk != nil {
                sodium.utils.zero(&self.fk!)
            }
            if self.dk != nil {
                sodium.utils.zero(&self.dk!)
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
            var mk = masterKey(from: password, salt: header!.salt)
            self.dk = sodium.keyDerivation.derive(secretKey: mk, index: 1, length: sodium.secretBox.KeyBytes , context: "Data")!
            self.fk = sodium.keyDerivation.derive(secretKey: mk, index: 2, length: sodium.secretBox.KeyBytes , context: "Files")!
            sodium.utils.zero(&mk)
            
            // Read the files box data.
            let filesTableData = try SealedFilesBox_FilesData(from: fileHandle, key: self.dk!, size: self.header!.sealedBoxDataSize)!
            self.filesTable = ExtendedFilesData(filesTableData)
            
        }
        
        /**
         Adds a file to the box in the given path and with the given name and contents.
         If a file in the same path and with the same name already exists the it throws the error:
         SealedFilesBoxError.FileAlreadyExists
         
         - Parameter in: The  path to the directory to add the file.
         It must be in the form: /subdir1/subdir2/  or / for adding the file to the root dir.
         
         - Parameter name: the name of the file to add including the extension, e.g. : example.txt
         
         - Parameter contents: the contents of the file.
         
         */
        public func addFile(in path: String, _ name: String, _ contents: Data) throws {
            guard path.trimmingCharacters(in:CharacterSet(charactersIn: " ")) != "",
                  path.starts(with: "/"),
                  path[path.index(before: path.endIndex)] == "/"
            else {
                throw SealedFilesBoxError.InvalidFilePath
            }
            
        }
        
        
        static public func create(named name: String, with password: String) throws -> Data {
            let sodium = Sodium()
            // Generate random salt.
            let salt = sodium.randomBytes.buf(length:sodium.pwHash.SaltBytes)!
            // let header = SealedFilesBoxHeader()
            
            // Derive the keys.
            var mk = masterKey(from: password, salt: Data(salt))
            
            guard var dk = sodium.keyDerivation.derive(secretKey: mk, index: 1, length: sodium.secretBox.KeyBytes , context: "Data") else {
                throw SealedFilesBoxError.LogicalError("can not derive key")
            }
            
            sodium.utils.zero(&mk)
            
            
            let filesData = SealedFilesBox_FilesData.with{
                data in
                data.name = name
                data.filesContentAreaOffset = UInt64(SealedFilesBoxHeader.size + SealedFilesBox.filesDataAreaMaxSize)
                data.filesContentAreaSize = 0
                data.rootDir = SealedFilesBox_DirectoryData.with{
                    rootDir in
                    // rootDir does not have name.
                    rootDir.name = ""
                    rootDir.files = [SealedFilesBox_DirectoryFile]()
                    rootDir.subdirectories = [SealedFilesBox_DirectoryData]()
                }
                data.fileList = [SealedFilesBox_FileListItem]()
            }
            
            
            let filesDataPayload = try filesData.serializedData()
            let filesDataCipherText: Bytes = sodium.secretBox.seal(message: [UInt8](filesDataPayload), secretKey: dk)!
            sodium.utils.zero(&dk)
            guard  filesDataCipherText.count < SealedFilesBox.filesDataAreaMaxSize else {
                throw SealedFilesBoxError.LogicalError("too many files in the box")
            }
            
            let dataPadCount = SealedFilesBox.filesDataAreaMaxSize - filesDataCipherText.count
            let pad: [UInt8] = [UInt8].init(repeating: 0, count: dataPadCount)
            var filesDataBytes = Data()
            filesDataBytes.append(Data(filesDataCipherText))
            filesDataBytes.append(Data(pad))
            
            let header  = SealedFilesBoxHeader(Data(salt), UInt64(filesDataCipherText.count))
            
            var payload = Data()
            payload.append(header.combined())
            payload.append(filesDataBytes)
            return payload
        }
        
        
    }
    
    struct SealedFilesBoxHeader {
        
        static var size: Int {
            let sodium = Sodium()
            // salt length + int64 for the length of the SealedBoxData.
            return sodium.pwHash.SaltBytes + 8
        }
        
        let salt: Data
        let sealedBoxDataSize: UInt64
        
        init(_ salt:Data, _ sealedBoxDataSize: UInt64) {
            self.salt = salt
            self.sealedBoxDataSize = sealedBoxDataSize
        }
        
        init?(from file: FileHandle) throws {
            guard #available(OSX 10.15.4, *) else {throw AbemError.operationNotSupported}
            guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
            let sodium = Sodium()
            
            // Read the salt.
            self.salt = try file.read(upToCount:sodium.pwHash.SaltBytes)!
            
            // Read the size of the sealed box data.
            let lenData = try file.read(upToCount: 8)!
            if lenData.count != 8 {
                throw Abem.SealedFilesBoxError.LogicalError("invalid sealed file")
            }
            
            self.sealedBoxDataSize = lenData.withUnsafeBytes{
                $0.load(as: UInt64.self)
            }
        }
        
        func combined() -> Data {
            var res = Data()
            res.append(self.salt)
            var size = self.sealedBoxDataSize
            let sizeData = Data(bytes: &size, count: MemoryLayout<UInt64>.size)
            res.append(Data(sizeData))
            return res
        }
        
    }
    
    struct ExtendedFilesData {
        let basicData: SealedFilesBox_FilesData
        let index: filesIndex
        init(_ data: SealedFilesBox_FilesData) {
            self.basicData = data
            self.index = data.buildIndex()
        }
    }
    
    public enum SealedFilesBoxError: Error {
        case LogicalError(_ Description: String)
        case FileAlreadyExists
        case InvalidFilePath
        case BoxClosed
    }
    
    
    public struct SealedFilesBoxFile {
        let box: SealedFilesBox
        let hash: Data
        public let fullName: URL
    }
    
    public struct SealedFilesBoxDirectory {
        let box: SealedFilesBox
        let directoryData: SealedFilesBox_DirectoryData
        public let fullName: URL
        
        public func Stat() throws -> [SealedFilesBoxFileInfo] {
            var infos = [SealedFilesBoxFileInfo]()
            self.directoryData.files.forEach{
                file in
                let fileURL = self.fullName.appendingPathComponent(file.name, isDirectory: false)
                let file = SealedFilesBoxFile(box: self.box, hash: file.fileHash, fullName: fileURL)
                infos.append(.File(file))
            }
            
            self.directoryData.subdirectories.forEach{
                dir in
                let dirURL = self.fullName.appendingPathComponent(dir.name, isDirectory: true)
                let dirInfo = SealedFilesBoxDirectory(box: self.box,directoryData: dir,fullName: dirURL)
                infos.append(.Directory(dirInfo))
            }
            return infos
        }
    }
    
    public enum SealedFilesBoxFileInfo {
        case File(SealedFilesBoxFile)
        case Directory(SealedFilesBoxDirectory)
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
