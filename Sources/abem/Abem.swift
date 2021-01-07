
import Foundation
import Sodium
import Security
import LocalAuthentication

public struct Abem {
    
    public struct CiphertextPayload {
        public let payload: Data
        public let metadata: String
        
        public init(_ ciphertext: Data, _ metadata: String) {
            self.payload = ciphertext
            self.metadata = metadata
        }
        
        public init? (From data: Data) {
            // Read size of the metadata.
            guard data.count > 0 else {return nil}
            let size = data[0]
            // Read the metadata.
            if size > 0 {
                guard data.count-1 >= size else {return nil}
                let metadataContents = data[1...Int(size)]
                let metadata = String(data: metadataContents, encoding: .utf8)
                guard metadata != nil else {return nil}
                self.metadata = metadata!
            } else {
                self.metadata = ""
            }
            let payload = data[Int(size)+1..<data.count]
            self.payload = payload
        }
        
        public func Combined() -> Data {
            // = sizeOf(metadata)||trim(metadata,256)||ciphertext
            let meta = self.metadata.prefix(255)
            var combined = Data()
            let size = UInt8(meta.count)
            combined.append(size)
            let metaD = meta.data(using: .utf8)!.prefix(255)
            combined.append(metaD)
            combined.append(self.payload)
            return combined
        }
    }
    
    public struct Ciphertext {
        public let ciphertext: Data
        public let salt: Data
        public init(from data:Data) {
            let saltSize = Sodium().pwHash.SaltBytes
            self.salt = data[0..<saltSize]
            let ciphertext = data[saltSize..<data.count]
            self.ciphertext = ciphertext
        }
        public init (_ ciphertext: Data,_ salt: Data) {
            self.ciphertext = ciphertext
            self.salt = salt
        }
        public func Combined()-> Data {
            var combined = Data(self.salt)
            combined.append(self.ciphertext)
            return combined
        }
    }
    
    /**
     Returns  a Ciphertext struct with the result of the encryption.
     
     - Parameter data: The  data to encrypt.
     
     - Parameter metadata: The metadata to encrypt together with the provided data, the size of the metadata must be
     up to 256 bytes, if it exceed that size it will be truncated.
     
     - Parameter pwd: The password to encrypt the data and metadata with.
     
     - Parameter passwordStrength: The strength the password must conform to for the function to do the
     Encryption operation.
     
     - Returns: The generated ciphertext.
     */
    public static func Encrypt(data: Data, metadata: String, with pwd: String, passwordStrength pStrength: PasswordStrength = .strong) throws -> Ciphertext? {
        
        guard #available(OSX 10.15, *) else {throw AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
        guard pwd.count > 0 else {throw AbemError.emptyPassword}
        guard PasswordStrength.Check(pwd) == pStrength else {throw AbemError.passwordTooWeek}
        let pwdBytes = pwd.bytes
        let sodium = Sodium()
        // Generate random salt.
        let salt = sodium.randomBytes.buf(length:sodium.pwHash.SaltBytes)!
        // Derive the encryption key from the password and the salt.
        let keySize = sodium.secretBox.KeyBytes
        var key = sodium.pwHash.hash(outputLength: keySize, passwd: pwdBytes, salt: salt, opsLimit: sodium.pwHash.OpsLimitModerate, memLimit: sodium.pwHash.MemLimitModerate)!
        // Encrypt using the derived key.
        let payload = CiphertextPayload(data, metadata)
        let cipherBytes: Bytes = sodium.secretBox.seal(message: [UInt8](payload.Combined()), secretKey: key)!
        sodium.utils.zero(&key)
        let cipherData = Data(cipherBytes)
        let ciphertext = Ciphertext(cipherData, Data(salt))
        return ciphertext
        
    }
    
    public static func Decrypt(_ ciphertext: Ciphertext, with pwd: String) throws -> CiphertextPayload {
        guard #available(OSX 10.15, *) else {throw AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
        guard pwd.count > 0 else {throw AbemError.emptyPassword}
        let sodium = Sodium()
        // Derive the encryption key from the password.
        let pwdBytes = pwd.bytes
        let salt = ciphertext.salt
        let keySize = sodium.secretBox.KeyBytes
        let key = sodium.pwHash.hash(outputLength: keySize, passwd: pwdBytes, salt: [UInt8](salt), opsLimit: sodium.pwHash.OpsLimitModerate, memLimit: sodium.pwHash.MemLimitModerate)!
        // Decrypt using the derived key.
        let contentBytes  = sodium.secretBox.open(nonceAndAuthenticatedCipherText: [UInt8](ciphertext.ciphertext), secretKey: key)
        guard let content = contentBytes else {throw AbemError.decryptError}
        let payload = CiphertextPayload(From: Data(content))
        guard payload != nil else {throw AbemError.internalError}
        return payload!
    }
    
    public enum AbemError: Error {
        case emptyPassword
        case internalError
        case operationNotSupported
        case passwordTooWeek
        case decryptError
    }
    
    
}

