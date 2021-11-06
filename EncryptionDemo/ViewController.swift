//
//  ViewController.swift
//  EncryptionDemo
//
//  Created by Mahendra Singh on 30/04/20.
//  Copyright © 2020 Mahendra Singh. All rights reserved.
//

import UIKit
import Security

class ViewController: UIViewController {
    
    let kPublicKeyTag = "com.apple.sample.publickey"
    let kPrivateKeyTag = "com.apple.sample.privatekey"
    let passPhrase = "test123"
    let serverPublicKeyHexStr = "0499945c32a9afb96a77df1bdb9bebe65840b4f29f81b2e2a59a5e656068e4e37b7801baeef1f6e3671980fa8baad6586a3dd5d061b083f2241207fbc49d42160b"
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    //Method to generate key pair and store private key in the keychain
    @IBAction func generateKeyPair() {
        var sanityCheck = noErr
        var publicKeyRef: SecKey? = nil
        var privateKeyRef: SecKey? = nil
        
        let privateTag = Data(bytes: kPrivateKeyTag.cString(using: .utf8)!, count: kPrivateKeyTag.utf8.count + 1)
        let publicTag = Data(bytes: kPublicKeyTag.cString(using: .utf8)!, count: kPublicKeyTag.utf8.count + 1)
        
        // Set top level dictionary for the keypair.
        let keyPairAttr: NSMutableDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits: 256]
        
        // Set the private key dictionary.
        let privateKeyAttr: NSDictionary = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: privateTag]
        
        // Set the public key dictionary.
        let publicKeyAttr: NSDictionary = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: publicTag]
        
        // Set attributes to top level dictionary.
        keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr
        keyPairAttr[kSecPublicKeyAttrs] = publicKeyAttr
        
        // SecKeyGeneratePair returns the SecKeyRefs
        sanityCheck = SecKeyGeneratePair(keyPairAttr, &publicKeyRef, &privateKeyRef)
        assert(sanityCheck == noErr && publicKeyRef != nil && privateKeyRef != nil, "Something went wrong with key pair [\(sanityCheck)].")
        
        //Delete all the stored keys first
        self.deleteAllSecKeys()
        
        //Store private key in the key chain
        self.savePrivateKey(key: privateKeyRef!, passPhrase: self.passPhrase)
        
    }
    
    //Fetch private key from key chain
    @IBAction func SecretFromKeyChain() {
        var error: Unmanaged<CFError>?
        
        let publicKeyAttrDic: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
        ]
        
        let serverPublicKeyHexStr = "04275629096d0f1854930722a27449b6558de5335a0dc1e6bf2197c867c3a5ff021d021303ee7119997e63690fe1ed6e44bf435d25bc4197e873fb24fdb6dfaefd"
        
        let pubKeyData = serverPublicKeyHexStr.hexadecimal
        let secKeyPub = SecKeyCreateWithData(pubKeyData! as CFData, publicKeyAttrDic as CFDictionary, &error)
        print(secKeyPub!)
        
        let secKeyPri = self.retrivePrivateKey(passPhrase: self.passPhrase)
        print(secKeyPri)
        
        let dict: [String: Any] = [:]
        
        //Generate secret key from server public key and user's private key
        let result =  SecKeyCopyKeyExchangeResult(secKeyPri, SecKeyAlgorithm.ecdhKeyExchangeCofactor, secKeyPub!, dict as CFDictionary, &error)
        
        let resData = result! as Data
        
        let hexSecret = resData.hexEncodedString()
        
        print(hexSecret)
        
    }
    
    //This example just to check if both the keys are in string format, means the private key in not stored in the key chain.
    @IBAction func secretFromStringKeys() {
        var error: Unmanaged<CFError>?
        
        let publicKeyAttrDic: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
        ]
        
        let privateKeyAttrDic: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 128,
        ]
        
        let serverPublicKeyHexStr = "04bfdbdc073a833771c02b40567b3c3f17066d5beabe97259b49a87ccabf228421a4b430b23b57c0bab8d0d97ddcd5576ce6b0ac7c364089c0b938a90efb814afd"
        
        let privateKeyHexStr = "04e895a5fe6cdb22502b8db049448c14ea0b2deb2a16dd2d81e349babe1521cdbc6e554255bb5ee0e1a8dca44ee78b437bafa686d058022b3406127b9a9495866136984f2acf1cc72c5953234a984664610247d2c284bcc6af1cc6c742b52394ce"
        
        let pubKeyData = serverPublicKeyHexStr.hexadecimal
        let secKeyPub = SecKeyCreateWithData(pubKeyData! as CFData, publicKeyAttrDic as CFDictionary, &error)
        print(secKeyPub!)
        
        let priKeyData = privateKeyHexStr.hexadecimal
        let secKeyPri = SecKeyCreateWithData(priKeyData! as CFData, privateKeyAttrDic as CFDictionary, &error)
        print(secKeyPri!)
        
        let dict: [String: Any] = [:]
        
        //Generate secret key from server public key and user's private key
        let result =  SecKeyCopyKeyExchangeResult(secKeyPri!, SecKeyAlgorithm.ecdhKeyExchangeCofactor, secKeyPub!, dict as CFDictionary, &error)
        
        let resData = result! as Data
        
        let hexSecret = resData.hexEncodedString()
        
        print(hexSecret)
    }
    
    //Generate secret from short keys
    @IBAction func secretFromStringKeysShort() {
        var error: Unmanaged<CFError>?
        
        let publicKeyAttrDic: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
        ]
        
        let privateKeyAttrDic: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 128,
        ]
    
        //Public key of user
        let publicKeyHexStr = "0424262d34e44ae6c41b6ea55a2ddfb7818b592133a03d41d0f3d547315e10726ceac06dcbdc3bcf577913b235b72049822326d31fbe074105d25ddcd7903d6c88"
        
        //Short private key of user
        let privateKeyHexStr = "bd35a4bb801a80cbffc8e6ce69fa76418b55d321e0386b864e06776cfb09e625"
        
        let serverPubKeyData = self.serverPublicKeyHexStr.hexadecimal
        
        let secKeyPub = SecKeyCreateWithData(serverPubKeyData! as CFData, publicKeyAttrDic as CFDictionary, &error)
        print(secKeyPub!)
        
        //Here we need to merge both keys to generate the long private key
        let pubKeyData = publicKeyHexStr.hexadecimal
        let priKeyData = privateKeyHexStr.hexadecimal
        let newPrivKey = pubKeyData! + priKeyData!
        let newpubkey = newPrivKey.dropLast(32)
        print(newpubkey.hexEncodedString())
        
        let secKeyPri = SecKeyCreateWithData(newPrivKey as CFData, privateKeyAttrDic as CFDictionary, &error)
        print(secKeyPri!)
        
        let dict: [String: Any] = [:]
        
        //Generate secret key from server public key and user's private key
        let result =  SecKeyCopyKeyExchangeResult(secKeyPri!, SecKeyAlgorithm.ecdhKeyExchangeCofactor, secKeyPub!, dict as CFDictionary, &error)
        
        let resData = result! as Data
        
        let hexSecret = resData.hexEncodedString()
        
        print(hexSecret)
    }
    
    //Export public and private key pair
    @IBAction func exportKeyPair() {
        var error: Unmanaged<CFError>?
        
        let secKeyPri = self.retrivePrivateKey(passPhrase: self.passPhrase)
        let keyBytes = SecKeyCopyExternalRepresentation(secKeyPri, &error) as Data?
        
        let keyData = keyBytes!
        let privateKeyData = keyData.dropFirst(65)
        let hexPriKey = privateKeyData.hexEncodedString()
        print(hexPriKey)
        
        let publicKeyData =  keyData.dropLast(keyData.count - 65)
        let hexPubKey = publicKeyData.hexEncodedString()
        print(hexPubKey)
    }
    
    //Save private key in keychain
    func savePrivateKey(key: SecKey, passPhrase: String) {
        let tag = passPhrase.data(using: .utf8)
        let attribute = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrApplicationTag): tag as Any,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeEC,
            String(kSecValueRef)           : key,
            String(kSecReturnPersistentRef): true
        ] as [String : Any]
        
        let status = SecItemAdd(attribute as CFDictionary, nil)
        if status != noErr {
            print("SecItemAdd Error!")
            return
        }
    }
    
    //Retrive private key from keychain by passphrase
    func retrivePrivateKey(passPhrase: String) -> SecKey {
        let tag = passPhrase.data(using: .utf8)
        let query: [String: Any] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrApplicationTag): tag as Any,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeEC,
            String(kSecReturnRef)         : true as Any
        ]
        
        var result : AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            return result as! SecKey
        }
        let seckeyRef: SecKey? = nil
        return seckeyRef!
    }
    
    //Delete all the keys from keychain
    func deleteAllSecKeys() {
        let query : [String: AnyObject] = [
            String(kSecClass): kSecClassKey
        ]
        let status = SecItemDelete(query as CFDictionary)
        
        switch status {
        case errSecItemNotFound:
            print("No key found in the keychain")
        case noErr:
            print("All the Keys Deleted!")
        default:
            print("SecItemDelete error! \(status.description)")
        }
    }
}

extension Data {
    //Generate HexEncodingOptions from data
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    
    //Hex string from data
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}

extension String {
    //Data from Hesadecimal string
    var hexadecimal: Data? {
        var data = Data(capacity: lengthOfBytes(using: .utf8) / 2)
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }
        guard data.count > 0 else { return nil }
        return data
    }
}
