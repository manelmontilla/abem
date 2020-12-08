import CryptoKit
import Foundation
import Sodium
import Security
import LocalAuthentication

struct Abem {

    struct Ciphertext {
        let ciphertext: Data
        let salt: Data
    }

    public static func Encrypt(data: Data, with pwd: String) throws -> Ciphertext? {
        guard #available(OSX 10.15, *) else {throw AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
        let pwdBytes = pwd.bytes
        let sodium = Sodium()
        // Generate random salt.
        var salt = [UInt8](repeating: 0, count: sodium.pwHash.SaltBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, sodium.pwHash.SaltBytes, &salt)
        guard status == errSecSuccess else {throw AbemError.internalError}
        // Derive the encryption key from the password.
        let key = sodium.pwHash.hash(outputLength: 256/8, passwd: pwdBytes, salt: Bytes(salt), opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive)!
        // Encrypt using the derived key.
        let box = try AES.GCM.seal(data, using: SymmetricKey(data: key))
        let ciphertext = Ciphertext(ciphertext: box.combined!, salt: Data(salt))
        return ciphertext
    }

    public static func Decrypt(_ ciphertext: Ciphertext, with pwd: String) throws -> Data {
        guard #available(OSX 10.15, *) else {throw AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
        let sodium = Sodium()
        // Derive the encryption key from the password.
        let pwdBytes = pwd.bytes
        let salt = ciphertext.salt
        let key = sodium.pwHash.hash(outputLength: 256/8, passwd: pwdBytes, salt: [UInt8](salt), opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive)!
        // Dencrypt using the derived key.
        let skey =  SymmetricKey(data: key)
        let box = try AES.GCM.SealedBox(combined: ciphertext.ciphertext)
        let content = try AES.GCM.open(box, using: skey)
        return content
    }

    public static func storeInSecureEnclave(tag: String, key: Data, Salt: Data) throws {
        // TODO: Implement.
        /*guard #available(OSX 10.15, *) else {throw AbemError.operationNotSupported}
        guard #available(iOS 13.0, *) else {throw AbemError.operationNotSupported}
        guard SecureEnclave.isAvailable else {throw AbemError.operationNotSupported}
        let authContext = LAContext();
        let accessControl = SecAccessControlCreateWithFlags(
           kCFAllocatorDefault,
           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
           [.privateKeyUsage, .userPresence, .biometryCurrentSet],
           nil
        )!;
        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
          accessControl: accessControl,
          authenticationContext: authContext)*/

    }

    public static func check(password pwd: String) -> Bool {
        // password entropy H=L*log2(N)
        return true
    }

}

enum AbemError: Error {
    case readingFile(file: String)
    case internalError
    case operationNotSupported
}

enum PasswordStrength {
     case weak
     case strong
     public static func Check(_ password: String) -> PasswordStrength {
        var pools = Set<CharPool>()
        for c in password {
            let pool = CharPool.from(character: c)
            pools.insert(pool)
        }
        var poolLen = 0
        for pool in pools {
            poolLen += pool.length()
        }

        let entropy = Int(Double(password.count) * log2(Double(poolLen)))
        if entropy >= 60 {
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
    case nonASCII
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
             return 0
        }
    }

    static func from(character char: Character) -> CharPool {
        if char.isLetter {
            if char.isUppercase {
                return .uppercase
            } else {
                return .lowercase
            }
        }
        if char.isSymbol {
            return .symbols
        }
        if char.isNumber {
            return .numbers
        }
        return .nonASCII
    }

}
