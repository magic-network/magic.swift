//
//  Magic.swift
//  Magic
//
//  Created by Dominic Amato on 5/24/19.
//  Copyright © 2019 Magic. All rights reserved.
//

#if os(macOS)
import Cocoa
import Foundation
import CoreWLAN
import SecurityFoundation
import WiFiMobileConfig

extension CWNetwork {
    //override description since we want the ssid
    override open var description: String { return self.ssid! }
}


extension Magic.Connectivity {
    
    func getMagicNetworks() -> Set<CWNetwork> {
        return self.networks
    }
    
    func getCurrentInterface() -> CWInterface? {
        return self.currentInterface
    }
    
    func getAvailableInterfaces() -> [CWInterface] {
        return self.interfaces
    }
    
    private func getIdentity() -> SecIdentity? {
        //            let getquery: [String: Any] = [kSecClass as String: kSecClassIdentity,
        //                                           kSecAttrLabel as String: "Magic Identity",
        //                                           kSecReturnRef as String: kCFBooleanTrue]
        //            var item: CFTypeRef?
        //            let status = SecItemCopyMatching(getquery as CFDictionary, &item)
        //            if status != errSecSuccess {
        //                print("Error getting Identity \(SecCopyErrorMessageString(status, nil)!)")
        guard let certificate = grabBundleCertificate() else {
            print("Could not get certificate from app bundle...")
            return nil
        }
        
        let addquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                       kSecValueRef as String: certificate,
                                       kSecAttrLabel as String: "Magic Certificate"]
        
        let add_status = SecItemAdd(addquery as CFDictionary, nil)
        if add_status == errSecSuccess {
            var identity: SecIdentity?
            let status = SecIdentityCreateWithCertificate(nil, certificate, &identity)
            
            if status == errSecSuccess {
                let addquery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                               kSecValueRef as String: identity!,
                                               kSecAttrLabel as String: "Magic Identity"]
                
                let add_status = SecItemAdd(addquery as CFDictionary, nil)
                guard add_status == errSecSuccess else {
                    print("Could not install identity to keychain \(SecCopyErrorMessageString(add_status, nil)!)")
                    return nil
                }
                print("Installed identity to keychain")
                return identity
            } else {
                print("Could Not Create Identity: \(SecCopyErrorMessageString(status, nil)!)")
                return nil
            }
        }
        return nil
        
        //            }
        //            return (item as! SecIdentity)
    }
    
//    private func installOrRetrieveCertificate() -> SecCertificate? {
//
//        let getquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
//                                       kSecAttrLabel as String: "Magic Certificate",
//                                       kSecReturnRef as String: kCFBooleanTrue]
//        var item: CFTypeRef?
//        let status = SecItemCopyMatching(getquery as CFDictionary, &item)
//        if status != errSecSuccess {
//            print("Error getting certificate \(SecCopyErrorMessageString(status, nil)!)")
//            guard let certificate = grabBundleCertificate() else {
//                print("Could not get certificate from app bundle...")
//                return nil
//            }
//            let addquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
//                                           kSecValueRef as String: certificate,
//                                           kSecAttrLabel as String: "Magic Certificate"]
//
//            let add_status = SecItemAdd(addquery as CFDictionary, nil)
//            guard add_status == errSecSuccess else {
//                print("Could not install certificate to keychain \(SecCopyErrorMessageString(add_status, nil)!)")
//                return nil
//            }
//            print("Installed certificate to keychain")
//            return certificate
//        }
//        print("certificate is already installed")
//        return (item as! SecCertificate)
//    }
    
    // Fetch detectable WIFI networks
    func findNetworks(ssid: Data?) {
        do {
            self.networks = try currentInterface!.scanForNetworks(withSSID: ssid)
        } catch let error as NSError {
            print("Error: \(error.localizedDescription)")
        }
    }
    
    func connectToNetwork(network: Any, username: String, password: String, completion: @escaping (_ error: NetworkError?) -> Void) {
        guard let network = network as? CWNetwork else {
            return
        }
        print("Attempting to connect with username: \(username) and password: \(password)")
        let networkProfile = CWMutableNetworkProfile()
        networkProfile.ssidData = network.ssidData
        networkProfile.security = .wpa2Enterprise
        
        let networkConfig = CWMutableConfiguration()
        networkConfig.networkProfiles = [networkProfile]
        networkConfig.requireAdministratorForAssociation = false
        networkConfig.rememberJoinedNetworks = true
        
        let config = generateMobileConfig(ssid: network.ssid!, username: username, password: password)
        if !CommandLineInstaller.installed(config: config) {
            let result = CommandLineInstaller.install(mobileConfig: config, configName: "magic")
            if result != .success {
                print("failed installing network profile")
                Magic.EventBus.post(MagicStatus.error(.errorInstallingConfiguration))
                completion(.errorInstallingConfiguration)
                return
            }
            
            // We should only have to install a configuration if we haven't already.
            do {
                let flags: AuthorizationFlags = [.extendRights, .interactionAllowed]
                let auth: SFAuthorization = SFAuthorization()
                try auth.obtain(withRight: "system.preferences", flags: flags)
                try self.currentInterface!.commitConfiguration(networkConfig, authorization: auth)
            }
            catch {
                print("Authorization failed")
                Magic.EventBus.post(MagicStatus.error(.errorAuthorizingConfiguration))
                completion(.errorAuthorizingConfiguration)
                return
            }
        }
        
        queue.async {
            do {
                //In Swift, this method returns Void and is marked with the throws keyword to indicate that it throws an error in cases of failure.
                try self.currentInterface!.associate(toEnterpriseNetwork: network, identity: self.identity, username: username, password: password)
                Magic.EventBus.post(MagicStatus.connected)
                self.currentStatus = .connected
                completion(.success)
            } catch {
                print(error.localizedDescription)
                Magic.EventBus.post(MagicStatus.error(.errorConnectingToNetwork))
                completion(.errorConnectingToNetwork)
            }
        }
    }
    
    func disconnect() {
        self.currentInterface?.disassociate()
        Magic.EventBus.post(MagicStatus.disconnected)
        self.currentStatus = .disconnected
    }
    
    private func generateMobileConfig(ssid: String, username: String, password: String) -> MobileConfig {
        let configUUID = UUID.init()
        let payloadUUID = UUID.init()
        let certUUID = UUID.init()
        let certData = "MIIDwTCCAqmgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAklMMRAwDgYDVQQHDAdDaGljYWdvMREwDwYDVQQKDAhIb2xvZ3JhbTEgMB4GCSqGSIb3DQEJARYRYWRtaW5AZXhhbXBsZS5vcmcxLDAqBgNVBAMMI0V4YW1wbGUgTWFnaWMgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE5MDEyMzIwMzczNloXDTI4MTIwMTIwMzczNlowZzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAklMMREwDwYDVQQKDAhIb2xvZ3JhbTESMBAGA1UEAwwJc29tZXRoaW5nMSQwIgYJKoZIhvcNAQkBFhV3ZWJtYXN0ZXJAaG9sb2dyYW0uaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3aXXhSgwr1a/yQQgAhvvrO3g4Wglk3+pHJ8/2NOLTDWwA/wW/WfpPWn8i5+8UK0+7VN7i0YK3X0/G/JgojrEjYGF8yv4uyzwoKF/PjUuEmrRsYMlU+8FkICULBqd7uoVYnA/2uhRrEZu1HyVqCunMq0Oni7/qRYdXXmdCVRs+RG0HSFEEt3itx15hZzbmcX9UH3i2o8EP2AYrO2tEgPNcVgJfuqr/9rI/SkfNcU9tVqMmIp6fztRMP8G5P6sUi7aprVYFzOoC1TthEfFVtQ/0Jg2xzk2YoKqAUlMquR65fQmOfsE0bIQtMDalfondc9ABQu2Xydb6eSTpBsLmEmiLAgMBAAGjTzBNMBMGA1UdJQQMMAoGCCsGAQUFBwMBMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly93d3cuZXhhbXBsZS5jb20vZXhhbXBsZV9jYS5jcmwwDQYJKoZIhvcNAQELBQADggEBAAafDofsbg312GW5s9cGmfjwDXiDAD2zaV1FmV3IfOCylOj4TuSA2n8CS48vCkuBtwMVs02az7fpfwRVKnLO130BWbpE4u+sG+SWBP3WTxSXDiu4phjdmI3Hzl24a0M6bWgNxB9XS0fnsrhcuOwfATbZVzJmWHZrj+qKk69bPDH8TCcEShpAcCYY8b573SalVuO9RI7yDKY6V05giviGeBgWHawjHYrTVCw4XFz3G1Ekzh7Z/ypXvD+uk0C+IDcfNy7kOUiHAJhIGelPoY7/8paEVya/Ywe0agmNoWLFFRJUDD254ynx38tY9HAHzHYc+sWXhKhxCRYWHPIMUf5fAa8="
        
        // We can actually add more than one ssid in the payload content but it appears we can't update a profile once its installed
        return MobileConfig(
            contents: [
                MobileConfig.PayloadContent.wiFi(.init(
                    version: .init(version: 1),
                    identifier: .from(uuid: payloadUUID, type: .wiFi),
                    uuid: payloadUUID,
                    displayName: .init(displayName: "Magic Wireless"),
                    description: "Magic.co Wireless Hotspot profile",
                    organization: .init(organizationName: "Magic.co"),
                    ssid: SSID(ssid),
                    isHiddenNetwork: false,
                    isAutoJoinEnabled: false,
                    encryptionType: .wpa2eap(EAPClientConfig(eapTypes: [.TTLS], oneTimePass: nil, payloadCertAnchorUUID: [certUUID], tlsMax: "1.2", tlsMin: "1.0", tlsTrustedServers: nil, ttlsInnerAuth: .PAP, username: Username(username), password: Password(password), outerIdentity: nil, allowTrustExceptions: nil, certificateIsRequired: nil, usePAC: nil, provisionPAC: nil, provisionPACAnonymously: nil, numberOfRANDs: nil)),
                    hotspotType: .none,
                    proxy: .none,
                    isCaptiveBypassEnabled: false,
                    qosMarkingPolicy: .none
                    ))
            ],
            certificates: [Certificate(filename: "magic-wireless.cer", content: Data(base64Encoded: certData)!, description: "Adds a PKCS#1-formatted certificate", displayName: .init(displayName: "Magic Certificate Authority"), identifier: .from(uuid: certUUID, type: .cert), uuid: certUUID)],
            description: "Magic.co Wireless profile",
            displayName: .init(displayName: "\(ssid)-\(username)"),
            expired: Date(),
            identifier: .from(uuid: configUUID, type: .init(type: "co.magic")),
            organization: .init(organizationName: "Magic.co"),
            uuid: configUUID,
            isRemovalDisallowed: false,
            scope: .user,
            autoRemoving: .none,
            consentText: .init(consentTextsForEachLanguages: [
                .default: "Magic requires installing a profile to enable connections to this network",
                .en: "Magic requires installing a profile to enable connections to this network",
            ])
        )
    }
    
    internal func startMonitorEvent(_ delegate: CWEventDelegate) {
        do {
            CWWiFiClient.shared().delegate = delegate
            print("Start Monitor event!")
            try CWWiFiClient.shared().startMonitoringEvent(with: .bssidDidChange)
            try CWWiFiClient.shared().startMonitoringEvent(with: .linkDidChange)
            try CWWiFiClient.shared().startMonitoringEvent(with: .countryCodeDidChange)
            try CWWiFiClient.shared().startMonitoringEvent(with: .linkQualityDidChange)
            try CWWiFiClient.shared().startMonitoringEvent(with: .modeDidChange)
            try CWWiFiClient.shared().startMonitoringEvent(with: .powerDidChange)
            // try CWWiFiClient.shared().startMonitoringEvent(with: .rangingReportEvent)
            try CWWiFiClient.shared().startMonitoringEvent(with: .scanCacheUpdated)
            try CWWiFiClient.shared().startMonitoringEvent(with: .ssidDidChange)
            // try CWWiFiClient.shared().startMonitoringEvent(with: .virtualInterfaceStateChanged)
            
        } catch {
            print("Start error: \(error.localizedDescription)")
        }
        
    }
    
    func stopMonitorEvent() {
        do {
            try CWWiFiClient.shared().stopMonitoringAllEvents()
        } catch {
            print("Stop error: \(error.localizedDescription)")
        }
    }
}

extension Magic.Connectivity: CWEventDelegate {
    
    func clientConnectionInterrupted() {
        /* Tells the delegate that the connection to the Wi-Fi subsystem is temporarily interrupted. */
        print("clientConnectionInterrupted")
    }
    
    func clientConnectionInvalidated() {
        /* Tells the delegate that the connection to the Wi-Fi subsystem is permanently invalidated. */
        print("clientConnectionInvalidated")
    }
    
    func countryCodeDidChangeForWiFiInterface(withName interfaceName: String) {
        /* Tells the delegate that the currently adopted country code has changed. */
        print("countryCodeDidChangeForWiFiInterface")
    }
    
    func linkDidChangeForWiFiInterface(withName interfaceName: String) {
        /* Tells the delegate that the Wi-Fi link state changed.  */
        print("linkDidChangeForWiFiInterface")
    }
    
    func linkQualityDidChangeForWiFiInterface(withName interfaceName: String, rssi: Int, transmitRate: Double) {
        /* */
        print("Intf (\(interfaceName)) link qualitity changed RSSI:\(rssi), rate:\(transmitRate)")
    }
    
    func modeDidChangeForWiFiInterface(withName interfaceName: String) {
        print("modeDidChangeForWiFiInterface")
    }
    
    func powerStateDidChangeForWiFiInterface(withName interfaceName: String) {
        print("powerStateDidChangeForWiFiInterface")
    }
    
    func rangingReportEventForWiFiInterface(withName interfaceName: String, data rangingData: [Any], error err: Error) {
        print("rangingReportEventForWiFiInterface")
    }
    
    func scanCacheUpdatedForWiFiInterface(withName interfaceName: String) {
        do {
            self.networks = try currentInterface!.scanForNetworks(withSSID: nil)
            Magic.EventBus.post(MagicStatus.scanCompleted)
        } catch let error as NSError {
            print("Error: \(error.localizedDescription)")
        }
    }
    
    func ssidDidChangeForWiFiInterface(withName interfaceName: String) {
        // If the ssid changed and its not a magic one set things as disconnected
        if currentInterface?.ssid() != nil && Magic.Connectivity.shared.status == .connected {
            if !currentInterface!.ssid()!.hasPrefix("magic") {
                Magic.Connectivity.shared.currentStatus = .disconnected
                Magic.EventBus.post(MagicStatus.disconnected)
            }
        }
    }
}
#endif
