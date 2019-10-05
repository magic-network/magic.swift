//
//  Magic.swift
//  Magic
//
//  Copyright © 2019 Magic. All rights reserved.
//

import Foundation
import web3swift

#if os(macOS)
import CoreWLAN
#elseif os(iOS)
import NetworkExtension
#endif

public enum NetworkError: Error {
    case success
    case noEAPSettingsProvided
    case errorGettingConfiguration
    case errorConnectingToNetwork
    case errorInstallingConfiguration
    case errorAuthorizingConfiguration
}

enum MagicError: Error {
    case noAccount
    case failedToSaveToKeychain
    case keychainDataError
    case keychainDataMismatch
    case unhandledError(status: OSStatus)
}

enum MagicStatus: CustomStringConvertible, Equatable {
    case connected
    case disconnected
    case pending
    case enabled
    case disabled
    case scanCompleted
    case error(NetworkError)
    
    var description : String {
        switch self {
        case .connected:
            return "co.magic.connected"
        case .enabled:
            return "co.magic.enabled"
        case .disabled:
            return "co.magic.disabled"
        case .pending:
            return "co.magic.pending"
        case .disconnected:
            return "co.magic.disconnected"
        case .scanCompleted:
            return "co.magic.scan.completed"
        case .error:
            return "co.magic.error"
        }
    }
}

final class Magic {
    static let version = "0.0.1"
    
    static func clamp<T: Comparable>(min: T, max: T, input: T) -> T {
        if input < min {
            return min
        }
        
        if input > max {
            return max
        }
        
        return input
    }
    
    static func mapToRange<T: FloatingPoint>(input: T, in_min: T, in_max: T, out_min: T, out_max: T) -> T {
        //evidently the swift compiler can't handle this function on one line
        // The compiler is unable to type-check this expression in reasonable time; try breaking up the expression into distinct sub-expressions
        let lhs = (input - in_min) * (out_max - out_min)
        let rhs = (in_max - in_min) + out_min
        return lhs / rhs
    }
    
    private init(){
        // just make init private so we don't have people making multiple copies of the magic class
    }
    
    static func register() {
        //initialize magic singletons
        Connectivity.shared
        Account.shared
    }
    
    class Connectivity {
        static let shared = Connectivity()
        var status: MagicStatus {
            return network.status
        }
        
        protocol MagicNetwork {
            internal var interfaces: [Any] = []
            internal var networks: Set<Any> = []
            internal var status: MagicStatus
            internal var lastActiveMagicNetwork: String?
            
            func getMagicNetworks() -> Set<Any>
            
            func getCurrentInterface() -> CWInterface?
        }
        
        private var network: MagicNetwork
        
        internal var app_certificate: SecCertificate?
        
        #if os(macOS)
        
        private init() {
            currentStatus = .disconnected
            
            self.interfaces = wifiClient.interfaces() ?? []
            
            self.identity = getIdentity()
            
            if let defaultInterface = CWWiFiClient.shared().interface() {
                self.currentInterface = defaultInterface
                findNetworks(ssid: nil)
                if let ssid = defaultInterface.ssid() {
                    if ssid.hasPrefix("magic") {
                        currentStatus = .connected
                    }
                }
            }
            
            CWWiFiClient.shared().delegate = self
            startMonitorEvent(self)
        }
        #endif
        
        #if os(iOS)
        private var lastActiveMagicNetwork: String?
        
        private init() {
            currentStatus = .disconnected
            installCertificate()
            setupNetworkMonitor()
            
            if currentSSID().hasPrefix("magic") {
                currentStatus = .connected
                lastActiveMagicNetwork = currentSSID()
                Magic.EventBus.post(MagicStatus.connected)
            }
        }
        #endif
        // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/certificates/storing_a_certificate_in_the_keycha
        private func installCertificate() {
            
            let getquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                           kSecAttrLabel as String: "Magic Certificate",
                                           kSecReturnRef as String: kCFBooleanTrue]
            var item: CFTypeRef?
            let get_status = SecItemCopyMatching(getquery as CFDictionary, &item)
            guard get_status == errSecSuccess else {
                print("Could not find certificate in keychain \(SecCopyErrorMessageString(get_status, nil)!)")
                guard let certificate = grabBundleCertificate() else {
                    print("Could not get certificate from app bundle...")
                    return
                }
                app_certificate = certificate
                let addquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                               kSecValueRef as String: certificate,
                                               kSecAttrLabel as String: "Magic Certificate"]
                
                let add_status = SecItemAdd(addquery as CFDictionary, nil)
                guard add_status == errSecSuccess else {
                    print("Could not install certificate to keychain \(SecCopyErrorMessageString(add_status, nil)!)")
                    return
                }
                print("Installed certificate to keychain")
                return
            }
            print("certificate is already installed")
            app_certificate = (item as! SecCertificate)
        }
        
        private func grabBundleCertificate() -> SecCertificate? {
            guard let certFile = Bundle.main.path(forResource: "server", ofType:"der") else {
                print("File not found...")
                return nil
            }
            
            guard let certData = NSData.init(contentsOfFile: certFile) else {
                print("Could not load data")
                return nil
            }
            
            guard let certificate = SecCertificateCreateWithData(nil, certData) else {
                print("Could not convert to certificate, may not be formatted properly")
                return nil
            }
            
            return certificate
        }
    }
    
    class Account {
        public static let shared = Account()
        private var address: String = ""
        private var key: Data = Data()
        
        private init() {
            do {
                try retrieveAccountFromKeychain()
            } catch {
                // account isn't saved or corrupted
                print("No account found in keychain, generating new account")
                createAccount()
            }
        }
        
        deinit {
            if !address.isEmpty && !key.isEmpty {
                do {
                    try saveAccount()
                    print("Saved account to keychain")
                } catch {
                    print("failed to save account to keychain")
                }
            }
        }
        
        func isValid() -> Bool {
            // these don't seem to match up...
            // && getPrivateKey() == self.key.toHexString()
            return !self.address.isEmpty && !self.key.isEmpty
        }
        
        func getAddress() -> String {
            return self.address
        }
        
        func getUsername() -> String {
            return self.address
        }
        
        func signWithTimestamp(timestamp: TimeInterval) -> String? {
            let message = "auth_\(Int(timestamp))".sha3(.keccak256)
            let privateKey = getPrivateKey()
            let (compressedSignature, _) = SECP256K1.signForRecovery(hash: Data(hex:message), privateKey: Data(hex: privateKey), useExtraEntropy: false)
            
            return compressedSignature!.toHexString()
        }
        
        private func getPrivateKey() -> String {
            let ethereumAddress = EthereumAddress(self.address)!
            let pkData = try! getKeystoreManager().UNSAFE_getPrivateKeyData(password: "", account: ethereumAddress).toHexString()
            return pkData
        }
        
        private func getKeystoreManager() -> KeystoreManager {
            let keystoreManager: KeystoreManager
            // Currently we don't use advanced keystores
            //        if wallet.isHD {
            //            let keystore = BIP32Keystore(data)!
            //            keystoreManager = KeystoreManager([keystore])
            //        } else {
            let keystore = EthereumKeystoreV3(self.key)!
            keystoreManager = KeystoreManager([keystore])
            //        }
            return keystoreManager
        }
        
        func createAccount() {
            let keystore = try! EthereumKeystoreV3(password: "")!
            self.key = try! JSONEncoder().encode(keystore.keystoreParams)
            self.address = keystore.addresses!.first!.address
        }
        
        func setAccountFromKey(privateKey: String) {
            let formattedKey = privateKey.trimmingCharacters(in: .whitespacesAndNewlines)
            let dataKey = Data.fromHex(formattedKey)!
            let keystore = try! EthereumKeystoreV3(privateKey: dataKey, password: "")!
            self.key = try! JSONEncoder().encode(keystore.keystoreParams)
            self.address = keystore.addresses!.first!.address
        }
        
        func saveAccount() throws {
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                        kSecAttrAccount as String: self.address,
                                        kSecAttrLabel as String: "Magic Credentials",
                                        kSecValueData as String: getPrivateKey()]
            let status = SecItemAdd(query as CFDictionary, nil)
            if status != errSecSuccess { if status != errSecDuplicateItem { throw MagicError.failedToSaveToKeychain} else {print("Account already in keychain")}}
        }
        
        private func retrieveAccountFromKeychain() throws {
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                        kSecMatchLimit as String: kSecMatchLimitOne,
                                        kSecAttrLabel as String: "Magic Credentials",
                                        kSecReturnAttributes as String: true,
                                        kSecReturnData as String: true]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            if status == errSecSuccess {
                guard let existingItem = item as? [String : Any],
                    let passwordData = existingItem[kSecValueData as String] as? Data,
                    let priv_key = String(data: passwordData, encoding: String.Encoding.utf8),
                    let address = existingItem[kSecAttrAccount as String] as? String
                    else {
                        throw MagicError.keychainDataError
                }
                setAccountFromKey(privateKey: priv_key)
                if self.address != address {
                    //Happens if the private key does not match the address retrieved
                    throw MagicError.keychainDataMismatch
                }
            }
            throw MagicError.unhandledError(status: status)
        }
    }
    
    open class EventBus {
        
        struct Static {
            static let instance = Magic.EventBus()
            static let queue = DispatchQueue(label: "co.magic.EventBus", attributes: [])
        }
        
        struct NamedObserver {
            let observer: NSObjectProtocol
            let name: String
        }
        
        var cache = [UInt:[NamedObserver]]()
        
        
        ////////////////////////////////////
        // Publish
        ////////////////////////////////////
        
        
        open class func post(_ status: MagicStatus, sender: Any? = nil) {
            NotificationCenter.default.post(name: Notification.Name(rawValue: status.description), object: sender)
        }
        
        open class func post(_ name: String, sender: Any? = nil) {
            NotificationCenter.default.post(name: Notification.Name(rawValue: name), object: sender)
        }
        
        open class func post(_ name: String, sender: NSObject?) {
            NotificationCenter.default.post(name: Notification.Name(rawValue: name), object: sender)
        }
        
        open class func post(_ name: String, sender: Any? = nil, userInfo: [AnyHashable: Any]?) {
            NotificationCenter.default.post(name: Notification.Name(rawValue: name), object: sender, userInfo: userInfo)
        }
        
        open class func postToMainThread(_ status: MagicStatus, sender: Any? = nil) {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Notification.Name(rawValue: status.description), object: sender)
            }
        }
        
        open class func postToMainThread(_ name: String, sender: Any? = nil) {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Notification.Name(rawValue: name), object: sender)
            }
        }
        
        open class func postToMainThread(_ name: String, sender: NSObject?) {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Notification.Name(rawValue: name), object: sender)
            }
        }
        
        open class func postToMainThread(_ name: String, sender: Any? = nil, userInfo: [AnyHashable: Any]?) {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Notification.Name(rawValue: name), object: sender, userInfo: userInfo)
            }
        }
        
        open class func postToMainThread(_ status: MagicStatus, sender: Any? = nil, userInfo: [AnyHashable: Any]?) {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Notification.Name(rawValue: status.description), object: sender, userInfo: userInfo)
            }
        }
        
        
        
        ////////////////////////////////////
        // Subscribe
        ////////////////////////////////////
        
        @discardableResult
        open class func on(_ target: AnyObject, name: String, sender: Any? = nil, queue: OperationQueue?, handler: @escaping ((Notification?) -> Void)) -> NSObjectProtocol {
            let id = UInt(bitPattern: ObjectIdentifier(target))
            let observer = NotificationCenter.default.addObserver(forName: NSNotification.Name(rawValue: name), object: sender, queue: queue, using: handler)
            let namedObserver = NamedObserver(observer: observer, name: name)
            
            Static.queue.sync {
                if let namedObservers = Static.instance.cache[id] {
                    Static.instance.cache[id] = namedObservers + [namedObserver]
                } else {
                    Static.instance.cache[id] = [namedObserver]
                }
            }
            
            return observer
        }
        
        @discardableResult
        open class func onMainThread(_ target: AnyObject, status: MagicStatus, sender: Any? = nil, handler: @escaping ((Notification?) -> Void)) -> NSObjectProtocol {
            return Magic.EventBus.on(target, name: status.description, sender: sender, queue: OperationQueue.main, handler: handler)
        }
        
        @discardableResult
        open class func onMainThread(_ target: AnyObject, name: String, sender: Any? = nil, handler: @escaping ((Notification?) -> Void)) -> NSObjectProtocol {
            return Magic.EventBus.on(target, name: name, sender: sender, queue: OperationQueue.main, handler: handler)
        }
        
        @discardableResult
        open class func onBackgroundThread(_ target: AnyObject, status: MagicStatus, sender: Any? = nil, handler: @escaping ((Notification?) -> Void)) -> NSObjectProtocol {
            return Magic.EventBus.on(target, name: status.description, sender: sender, queue: OperationQueue(), handler: handler)
        }
        
        @discardableResult
        open class func onBackgroundThread(_ target: AnyObject, name: String, sender: Any? = nil, handler: @escaping ((Notification?) -> Void)) -> NSObjectProtocol {
            return Magic.EventBus.on(target, name: name, sender: sender, queue: OperationQueue(), handler: handler)
        }
        
        ////////////////////////////////////
        // Unregister
        ////////////////////////////////////
        
        open class func unregister(_ target: AnyObject) {
            let id = UInt(bitPattern: ObjectIdentifier(target))
            let center = NotificationCenter.default
            
            Static.queue.sync {
                if let namedObservers = Static.instance.cache.removeValue(forKey: id) {
                    for namedObserver in namedObservers {
                        center.removeObserver(namedObserver.observer)
                    }
                }
            }
        }
        
        open class func unregister(_ target: AnyObject, name: String) {
            let id = UInt(bitPattern: ObjectIdentifier(target))
            let center = NotificationCenter.default
            
            Static.queue.sync {
                if let namedObservers = Static.instance.cache[id] {
                    Static.instance.cache[id] = namedObservers.filter({ (namedObserver: NamedObserver) -> Bool in
                        if namedObserver.name == name {
                            center.removeObserver(namedObserver.observer)
                            return false
                        } else {
                            return true
                        }
                    })
                }
            }
        }
    }
}