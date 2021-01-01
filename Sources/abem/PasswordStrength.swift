//
//  File.swift
//  
//
//  Created by Manel Montilla on 30/12/20.
//

import Foundation

extension Abem {
    
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
         - Rest. Contains all the rest of the chars that can be encoded using 1 byte, size: 162.
         
         The function considers all the passwords with less than 8 chars or with an entropy less than 50 bits weak.
         Take into account that the function divides the pools where a character belongs to considering only the English
         Alphabet.
         
         - Parameter password: A string containing the password to check.
         
         - Returns: The PasswordStrength.
         */
        public static func Check(_ password: String) -> PasswordStrength {
            guard password.count > 7 else {return .weak}
            let entropy = Entropy(for: password)
            if entropy >= 50 {
                return .strong
            }
            return .weak
        }
        
        public static func Entropy(for password:String) -> Double {
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
            let entropy = Double(password.count) * log2(Double(poolLen))
            return entropy
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
}
