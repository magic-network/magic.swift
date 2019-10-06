//
//  Magic.swift
//  Magic
//
//  Copyright © 2019 Magic. All rights reserved.
//

#if os(iOS)
import Foundation
import NetworkExtension
import UIKit
import UserNotifications
import SystemConfiguration.CaptiveNetwork

@available(iOS 12.0, *)
internal class iOSMagicInterface: MagicInterface {
    internal var status: MagicStatus
    
    internal var lastActiveMagicNetwork: String?
    
    init() {
        self.status = .disconnected
//        setupNetworkMonitor()
        
        if currentSSID()?.hasPrefix("magic") ?? false {
            self.status = .connected
            lastActiveMagicNetwork = currentSSID()
            Magic.EventBus.post(MagicStatus.connected)
        }
    }
    
    func getMagicNetworks() -> [String: Any] {
        return [:]
    }
    
    func getCurrentInterface() -> Any? {
        return NEHotspotHelper.supportedNetworkInterfaces()?[0]
    }
    
    func getAvailableInterfaces() -> [Any] {
        return NEHotspotHelper.supportedNetworkInterfaces() ?? []
    }
    
    func findNearbyMagicNetworks() { }
    
    func connect(ssid: String) {
        let connectionNotification = UNMutableNotificationContent()
        let ud = UserDefaults.standard
        
        if(ssid == currentSSID()){
            print("you were already connected to the network silly")
            self.status = .connected
            self.lastActiveMagicNetwork = ssid
            Magic.EventBus.post(self.status)
        }
        
        if Magic.Account.shared.isValid() {
            var configuration: NEHotspotConfiguration?
            
            let timestamp = NSDate().timeIntervalSince1970
            let pw = "\(timestamp)-\(Magic.Account.shared.signWithTimestamp(timestamp: timestamp))"
            // We switch username and password because iOS limits passwords to 64 characters and usernames to 253
            configuration = NEHotspotConfiguration(ssid: ssid, eapSettings: generateEAPSettings(username: pw, password: Magic.Account.shared.getAddress()))
            
            guard let networkConfiguration = configuration else {
                connectionNotification.title = "Failed"
                connectionNotification.body = "Error creating configuration for network"
                UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.connect.failed", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                    
                })
                self.status = .error(.errorGettingConfiguration)
                Magic.EventBus.post(self.status)
                return
            }
            
            NEHotspotConfigurationManager.shared.apply(networkConfiguration) { (error) in
                // TODO: we have a slight issue here, even when its unable to join the network we get no error so it sends a success state
                if error != nil {
                    if (error! as! NEHotspotConfigurationError).code == .alreadyAssociated {
                        print("Already connected to the network")
                        self.status = .connected
                        self.lastActiveMagicNetwork = ssid
                        Magic.EventBus.post(self.status)
                    } else {
                        connectionNotification.title = "Failed"
                        connectionNotification.subtitle = "Could not connect to network \(ssid)"
                        connectionNotification.body = "Error: \(error!.localizedDescription)"
                        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.connect.failed", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                            
                        })
                        self.status = .error(.errorConnectingToNetwork)
                        Magic.EventBus.post(self.status)
                    }
                } else {
                    if self.currentSSID() != ssid {
                        self.status = .error(.errorConnectingToNetwork)
                        Magic.EventBus.post(self.status)
                    } else {
                        if ud.bool(forKey: "magic.notification.connect") {
                            
                            connectionNotification.title = "Connected"
                            connectionNotification.body = "You are now connected to \(ssid)"
                            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.connect.success", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                                
                            })
                        }
                        self.status = .connected
                        self.lastActiveMagicNetwork = ssid
                        Magic.EventBus.post(self.status)
                    }
                }
            }
        } else {
            connectionNotification.title = "Failed"
            connectionNotification.body = "Your magic account is invalid"
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.connect.failed", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                
            })
            self.status = .error(.errorGettingConfiguration)
            Magic.EventBus.post(self.status)
        }
    }
    
    private func removeMagicConfig(_ ssid: String) {
        NEHotspotConfigurationManager.shared.removeConfiguration(forSSID: ssid)
        lastActiveMagicNetwork = nil
    }
    
    private func removeMagicConfigAndDisconnect(_ ssid: String) {
        removeMagicConfig(ssid)
        self.status = .disconnected
        Magic.EventBus.post(MagicStatus.disconnected)
    }
    
    fileprivate func setDisconnected() {
        //Don't disconnect from the network just set our status to disconnected
        self.status = .disconnected
        Magic.EventBus.post(self.status)
    }
    
    func disconnect() {
        if currentSSID()?.hasPrefix("magic") ?? false  {
            removeMagicConfigAndDisconnect(currentSSID()!)
        } else if let magicNetwork = lastActiveMagicNetwork {
            removeMagicConfigAndDisconnect(magicNetwork)
        } else {
            setDisconnected()
        }
    }
    
    func generateEAPSettings(username: String, password: String) -> NEHotspotEAPSettings {
        let hotspotEAPSettings = NEHotspotEAPSettings()
        hotspotEAPSettings.username = username
        hotspotEAPSettings.password = password
        hotspotEAPSettings.isTLSClientCertificateRequired = true
        hotspotEAPSettings.supportedEAPTypes = [NEHotspotEAPSettings.EAPType.EAPTTLS.rawValue] as [NSNumber]
        hotspotEAPSettings.ttlsInnerAuthenticationType = .eapttlsInnerAuthenticationPAP
        hotspotEAPSettings.setTrustedServerCertificates([Magic.Connectivity.shared.magicCertificate])
        return hotspotEAPSettings
    }
    
    func currentSSID() -> String? {
        if let interfaces = CNCopySupportedInterfaces() {
            for interface in interfaces as! [CFString] {
                if let unsafeInterfaceData = CNCopyCurrentNetworkInfo(interface) {
                    let interfaceData = unsafeInterfaceData as Dictionary
                    return interfaceData[kCNNetworkInfoKeySSID] as! String
                }
            }
        }
        return nil
    }
    
    // Should really be a better way to do this
//    func setupNetworkMonitor() {
//        // Can we get the gateways uri/ip to use for this?
//        var sock = sockaddr()
//        sock.sa_len = UInt8(MemoryLayout<sockaddr>.size)
//        sock.sa_family = sa_family_t(AF_INET)
//        guard let ref = SCNetworkReachabilityCreateWithAddress(kCFAllocatorDefault, &sock) else {
//            print("Failed to create Reachability")
//            return
//        }
//
//        var context = SCNetworkReachabilityContext(version: 0, info: nil, retain: nil, release: nil, copyDescription: nil)
//
//        guard SCNetworkReachabilitySetCallback(ref, { (reachability, flags, info) in
//            // evidently we can't use self in callbacks for this function
//            if !flags.contains(.reachable) || flags.contains(.isWWAN) {
//                // When we are switching networks it first triggers with unreachable but with a ssid
//                // if the ssid is empty than we actaully have been disconnected
//                if Magic.Connectivity.shared.network.currentSSID()?.isEmpty && Magic.Connectivity.shared.network.lastActiveMagicNetwork != nil {
//                    // The network state changed, maybe the internet went down or we moved out of range
//                    // but we can't reach the internet so disconnect
//                    removeMagicConfigAndDisconnect(lastActiveMagicNetwork!)
//                }
//            } else if flags.contains(.reachable) {
//                // if we are connected but not to a magic network, don't disconnect from that network but remove magic config
//                if !Magic.Connectivity.shared.network.currentSSID().hasPrefix("magic") && Magic.Connectivity.shared.network.lastActiveMagicNetwork != nil {
//                    removeMagicConfigAndDisconnect(Magic.Connectivity.shared.network.lastActiveMagicNetwork!)
//                } else if Magic.Connectivity.shared.network.currentSSID().hasPrefix("magic") && Magic.Connectivity.shared.network.lastActiveMagicNetwork != nil && Magic.Connectivity.shared.network.currentSSID() != Magic.Connectivity.shared.network.lastActiveMagicNetwork {
//                    // We connected to a new magic network, forget the old configuration
//                    removeMagicConfig(Magic.Connectivity.shared.network.lastActiveMagicNetwork!)
//                }
//            }
//        }, &context) else {
//            print("Failed to set callback")
//            return
//        }
//        // Only triggers in foreground currently
//        guard SCNetworkReachabilitySetDispatchQueue(ref, .main) else {
//            SCNetworkReachabilitySetCallback(ref, nil, nil)
//            print("Failed to add to dispatch queue")
//            return
//        }
//
//        print("Successfully registered network status monitor")
//    }
}
#endif
