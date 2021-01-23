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
                let rootURL = URL(string:"/")
                let directoryInfo = SealedFilesBoxDirectory(directoryData: r,fullName: rootURL!)
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
            guard #available(OSX 10.15.4, *) else {throw AbemError.operationNotSupported}
            guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
            guard file.startAccessingSecurityScopedResource() else {throw
                Abem.SealedFilesBoxError.LogicalError("can not access file: \(file.absoluteString)")
            }
            defer {file.stopAccessingSecurityScopedResource()}
            self.file = file
            // Open the handler for reading.
            let fileHandle = try FileHandle(forReadingFrom: file)
            defer {try? fileHandle.close()}
            
            
            // Read the header.
            let headerContents = try fileHandle.read(upToCount: SealedFilesBoxHeader.size)
            guard let contents = headerContents  else {
                throw SealedFilesBoxError.FileIsInvalid
            }
            self.header = try SealedFilesBoxHeader(contents: contents)
            
            
            let sodium = Sodium()
            
            // Derive the keys.
            var mk = masterKey(from: password, salt: header!.salt)
            self.dk = sodium.keyDerivation.derive(secretKey: mk, index: 1, length: sodium.secretBox.KeyBytes , context: "Data")!
            self.fk = sodium.keyDerivation.derive(secretKey: mk, index: 2, length: sodium.secretBox.KeyBytes , context: "Files")!
            sodium.utils.zero(&mk)
            
            // Read the files table.
            let ciphertext = try fileHandle.read(upToCount: Int(header!.sealedBoxDataSize))!
            let contentBytes  = sodium.secretBox.open(nonceAndAuthenticatedCipherText: [UInt8](ciphertext), secretKey: self.dk!)
            guard let content = contentBytes else {  throw Abem.SealedFilesBoxError.LogicalError("invalid sealed file") }
            self.filesTable = try ExtendedFilesData(from: Data(content))
            
        }
        
        /**
         Adds a file to the box in the given path and with the given name and contents.
         If a file in the same path and with the same name already exists the it throws the error:
         SealedFilesBoxError.FileAlreadyExists
         
         - Parameter in: The  directory to add the File.
         
         - Parameter named: the name of the file to add including the extension, e.g. : example.txt
         
         - Parameter containing: the contents of the file.
         
         */
        public func addFile(in dir: SealedFilesBoxDirectory, named name: String, containing data: Data)  throws -> SealedFilesBoxDirectory  {
            guard #available(OSX 10.15.4, *) else {throw AbemError.operationNotSupported}
            guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
            
            let file = self.file
            let sodium = Sodium()
            // Get the hash for the contents of the file.
            let hash = sodium.genericHash.hash(message: [UInt8](data))
            guard let h = hash else {
                throw SealedFilesBoxError.LogicalError("unable to generate hash")
            }
            
            // Encrypt the data of the new file.
            let fileContentCiphertext: Bytes? = sodium.secretBox.seal(message: Bytes(data), secretKey: self.fk!)
            guard let fileCiphertext = fileContentCiphertext else {
                throw SealedFilesBoxError.LogicalError("unable to encrypt data")
            }
            
            // Write the data to the file data area of the box.
            let fileHandle = try FileHandle(forUpdating: file)
            defer {
                try! fileHandle.close()
            }
            let last = try fileHandle.seekToEnd()
            fileHandle.write(Data(fileCiphertext))
            
            // Add the file to fileTable in the proper directory.
            let fileItem = SealedFilesBox_FileListItem.with{
                item in
                item.hash = Data(h)
                item.offset = last
                item.deleted = false
                item.size = UInt64(fileCiphertext.count)
            }
            
            let addedInDir = try self.filesTable!.addFile(file: fileItem, in: dir, maned: name)
            
            // Write the fileTable to disk.
            let fileTableContents = try self.filesTable!.combined()
            guard fileTableContents.count < ExtendedFilesData.maxSize else {
                throw SealedFilesBoxError.MaxNumberOfFilesLimitReached
            }
            let ciphertext: Bytes? = sodium.secretBox.seal(message: Bytes(fileTableContents), secretKey: self.dk!)
            guard let cipher = ciphertext else {
                throw Abem.SealedFilesBoxError.LogicalError("unable to encrypt data")
            }
            try fileHandle.seek(toOffset: UInt64(SealedFilesBoxHeader.size))
            fileHandle.write(Data(cipher))
            
            
            // Update the header.
            let fileTableSize = cipher.count
            self.header = SealedFilesBoxHeader(self.header!.salt, UInt64(fileTableSize))
            let headerContents = self.header!.combined()
            // Write the header to the disk.
            try fileHandle.seek(toOffset: 0)
            fileHandle.write(headerContents)
            
            // Return the directory info were the file was added.
            return addedInDir
        }
        
        static public func create(named name: String, with password: String) throws -> Data {
            let sodium = Sodium()
            // Generate random salt.
            let salt = sodium.randomBytes.buf(length:sodium.pwHash.SaltBytes)!
            // Derive the keys.
            var mk = masterKey(from: password, salt: Data(salt))
            guard var dk = sodium.keyDerivation.derive(secretKey: mk, index: 1, length: sodium.secretBox.KeyBytes , context: "Data") else {
                throw SealedFilesBoxError.LogicalError("can not derive key")
            }
            sodium.utils.zero(&mk)
            let filesData = SealedFilesBox_FilesData.with{
                data in
                data.name = name
                data.filesContentAreaOffset = UInt64(SealedFilesBoxHeader.size + ExtendedFilesData.maxSize)
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
            guard  filesDataCipherText.count < ExtendedFilesData.maxSize else {
                throw SealedFilesBoxError.LogicalError("too many files in the box")
            }
            let dataPadCount = ExtendedFilesData.maxSize - filesDataCipherText.count
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
        
        init(contents:Data) throws {
            guard contents.count == SealedFilesBoxHeader.size else {
                throw SealedFilesBoxError.FileIsInvalid
            }
            let sodium = Sodium()
            let salt = contents[0..<sodium.pwHash.SaltBytes]
            let sizeData = contents[sodium.pwHash.SaltBytes..<contents.count]
            let size = sizeData.withUnsafeBytes{
                $0.load(as: UInt64.self)
            }
            self.salt = salt
            self.sealedBoxDataSize = size
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
        
        static let maxSize = 2 * (2 << 19) // 2 MB's.
        var basicData: SealedFilesBox_FilesData
        var index: filesIndex
        
        init(_ data: SealedFilesBox_FilesData) {
            self.basicData = data
            self.index = data.buildIndex()
        }
        
        init?(from content: Data) throws {
            self.basicData = try SealedFilesBox_FilesData(serializedData:content)
            self.index = self.basicData.buildIndex()
        }
        
        func combined() throws -> Data {
            let ret = try self.basicData.serializedData()
            return ret
        }
        
        mutating func addFile(file fileItem: SealedFilesBox_FileListItem, in dir: SealedFilesBoxDirectory, maned name: String) throws -> SealedFilesBoxDirectory {
            self.basicData.fileList.append(fileItem)
            let i = self.basicData.fileList.count
            // Add the file to the index of the box
            let fileHashBytes = Bytes(fileItem.hash)
            self.index[fileHashBytes] = i
            
            var components = dir.fullName.pathComponents
            if components[0] == "/" {
                components.remove(at: 0)
            }
            let fDirData = SealedFilesBox_DirectoryFile.with{
                f in
                f.name = name
                f.fileHash = fileItem.hash
            }
            
            // Add the file to the directory tree.
            let newDir = try self.basicData.rootDir.addFile(at: components, fDirData)
            let newDirInfo = SealedFilesBoxDirectory(directoryData: newDir, fullName: dir.fullName)
            return newDirInfo
        }
        
        func save(to file: FileHandle, using key: Bytes) throws -> Int {
            guard #available(OSX 10.15.4, *) else {throw Abem.AbemError.operationNotSupported}
            guard #available(iOS 13.0, *) else {throw Abem.AbemError.operationNotSupported}
            let data = try self.basicData.serializedData()
            let sodium = Sodium()
            let contentBytes: Bytes? = sodium.secretBox.seal(message: Bytes(data), secretKey: key)
            guard let content = contentBytes else {
                throw Abem.SealedFilesBoxError.LogicalError("unable to encrypt data")
            }
            
            guard content.count < ExtendedFilesData.maxSize else {
                throw SealedFilesBoxError.MaxNumberOfFilesLimitReached
            }
            file.write(Data(content))
            return content.count
        }
        
    }
    
    public enum SealedFilesBoxError: Error {
        case LogicalError(_ Description: String)
        case FileAlreadyExists
        case InvalidFilePath
        case BoxClosed
        case DirectoryDoesNotExist
        case MaxNumberOfFilesLimitReached
        case FileIsInvalid
    }
    
    public struct SealedFilesBoxFile {
        let hash: Data
        public let fullName: URL
    }
    
    public struct SealedFilesBoxDirectory {
        let directoryData: SealedFilesBox_DirectoryData
        public let fullName: URL
        
        public func Stat() throws -> [SealedFilesBoxFileInfo] {
            var infos = [SealedFilesBoxFileInfo]()
            self.directoryData.files.forEach{
                file in
                let fileURL = self.fullName.appendingPathComponent(file.name, isDirectory: false)
                let file = SealedFilesBoxFile(hash: file.fileHash, fullName: fileURL)
                infos.append(.File(file))
            }
            
            self.directoryData.subdirectories.forEach{
                dir in
                let dirURL = self.fullName.appendingPathComponent(dir.name, isDirectory: true)
                let dirInfo = SealedFilesBoxDirectory(directoryData: dir,fullName: dirURL)
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
    
    func buildIndex() ->  Abem.filesIndex {
        var index = Abem.filesIndex()
        for (i , file) in self.fileList.enumerated() {
            let h = [UInt8](file.hash)
            index[h] = i
        }
        return index
    }
    
}

extension SealedFilesBox_DirectoryData {
    
    mutating func addFile(at path: [String], _ file: SealedFilesBox_DirectoryFile ) throws -> SealedFilesBox_DirectoryData {
        if path.count == 0 || path[0] == "" {
            self.files.append(file)
            return self
        }
        var names = path
        let nodeName = path[0]
        for i in 0..<self.subdirectories.count {
            if self.subdirectories[i].name == nodeName {
                names.remove(at: 0)
                return try self.subdirectories[i].addFile(at: names, file)
                
            }
        }
        throw Abem.SealedFilesBoxError.DirectoryDoesNotExist
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
