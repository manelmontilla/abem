
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
            // Read the payload.
            if data.count <= size+1 {
                self.payload = Data()
                return
            }
            let payload = data[Int(size)+1..<data.count]
            self.payload = payload
        }
        
        public func Combined() -> Data {
            // = sizeOf(metadata)||trim(metadata,256)||ciphertext
            let meta = self.metadata.prefix(256)
            var combined = Data()
            let size = UInt8(meta.count)
            combined.append(size)
            var metaD = meta.data(using: .utf8)!
            // Depending on the metadata its encoding in utf8 can have more
            // than 256 bytes if any of the chars need more than 1 byte to be
            // encoded.
            if metaD.count > 256 {
                metaD.removeLast(metaD.count-256)
            }
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
     
     - Parameter metadata: The metadata to encrypt together with the provided data.
     
     - Parameter pwd: The password to encrypt the data and metadata with.
     
     - Parameter passwordStrength: The strength the password must conform to for the function to do the
     Encryption operation.
     
     - Returns: The generated ciphertext.
     */
    public static func Encrypt(data: Data, metadata: String, with pwd: String, passwordStrength pStrength: PasswordStrength = .strong) throws -> Ciphertext? {
        
        guard #available(OSX 10.15, *) else {throw AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
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
        let sodium = Sodium()
        // Derive the encryption key from the password.
        let pwdBytes = pwd.bytes
        let salt = ciphertext.salt
        let keySize = sodium.secretBox.KeyBytes
        let key = sodium.pwHash.hash(outputLength: keySize, passwd: pwdBytes, salt: [UInt8](salt), opsLimit: sodium.pwHash.OpsLimitModerate, memLimit: sodium.pwHash.MemLimitModerate)!
        // Dencrypt using the derived key.
        let contentBytes  = sodium.secretBox.open(nonceAndAuthenticatedCipherText: [UInt8](ciphertext.ciphertext), secretKey: key)
        let payload = CiphertextPayload(From: Data(contentBytes!))
        guard payload != nil else {throw AbemError.internalError}
        return payload!
    }
}

public enum AbemError: Error {
    case readingFile(file: String)
    case metadataTooLong
    case internalError
    case operationNotSupported
    case passwordTooWeek
}


public enum PasswordStrength {
    case weak
    case strong
    
    /**
     Returns  the strength of a user generated password.
     
     The function is only suitable for passwords containing ascii  characters.
     In case the password contains any non ascii character the function will consider those
     chars to belong to a pool of size 162 which is the number of chars in the extended ascii
     encoding.
     All the passwords with less than 8 chars are also considered weak.
     The function considers only the two defined cases .weak and .strong.
     To classify the password it calculates the password entropy using:
     E = len(password)*log2(Pools Size)
     The function considers following pools:
     - Lower case english chars, size: 26.
     - Upper case english chars, size: 26.
     - Numbers, size: 10.
     - Symbols, size: 32.
     - Rest. Contains all the rest of the chars that can be encoded using 1 byte, so size: 162.
      
      The function consideres all the passwords with less than 8 chars or with an entropy of less than 50 weak.
     
     - Parameter password: A string containing the password to check.
     
     - Returns: The PasswordStrength.
     */
    public static func Check(_ password: String) -> PasswordStrength {
        guard password.count > 7 else {return .weak}
        var pools = Set<CharPool>()
        for c in password {
            let pool = CharPool.from(character: c)
            pools.insert(pool)
        }
        var poolLen = 0
        for pool in pools {
            poolLen += pool.length()
        }
        
        // Password entropy H=L*log2(N).
        let entropy = Int(Double(password.count) * log2(Double(poolLen)))
        if entropy >= 50 {
            return .strong
        }
        return .weak
    }
}

enum CharPool {
    case uppercase
    case lowercase
    case symbols
    case numbers
    case others
    func length() -> Int {
        switch self {
            case .lowercase:
                return 26
            case .uppercase:
                return 26
            case .symbols:
                return 32
            case .numbers:
                return 10
            default:
                return 162
        }
    }

    static func from(character char: Character) -> CharPool {
        // Char must be ascii
        guard char.isASCII else {return .others}
        
        if char.isUppercase {
            return .uppercase
        }
        
        if char.isLowercase {
            return .lowercase
        }
        
        
        if char.isNumber {
            return .numbers
        }
        
        if char.isSymbol  {
            return .symbols
        }
        
        if char.isMathSymbol {
            return .symbols
        }
        
        if char.isPunctuation {
            return .symbols
        }
        
        return .others
    }
    
}

