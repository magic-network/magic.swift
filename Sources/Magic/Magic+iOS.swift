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

internal class iOSMagicNetwork: Magic.Connectivity.MagicNetwork {
    private var lastActiveMagicNetwork: String?
    
    private init() {
        status = .disconnected
        installCertificate()
        setupNetworkMonitor()
        
        if currentSSID().hasPrefix("magic") {
            currentStatus = .connected
            lastActiveMagicNetwork = currentSSID()
            Magic.EventBus.post(MagicStatus.connected)
        }
    }
    
    func getCurrentInterface() -> [Any]? {
        return NEHotspotHelper.supportedNetworkInterfaces()
    }
    
    func connect(ssid: String) {
        let connectionNotification = UNMutableNotificationContent()
        let ud = UserDefaults.standard
        
        if(ssid == currentSSID()){
            print("you were already connected to the network silly")
            self.currentStatus = .connected
            self.lastActiveMagicNetwork = ssid
            Magic.EventBus.post(self.status)
        }
        
        if Account.shared.isValid() {
            var configuration: NEHotspotConfiguration?
            
            let timestamp = NSDate().timeIntervalSince1970
            let pw = "\(timestamp)-\(Magic.Account.shared.signWithTimestamp(timestamp: timestamp)!)"
            // We switch username and password because iOS limits passwords to 64 characters and usernames to 253
            configuration = NEHotspotConfiguration(ssid: ssid, eapSettings: generateEAPSettings(username: pw, password: Account.shared.getAddress()))
            
            guard let networkConfiguration = configuration else {
                connectionNotification.title = "Failed"
                connectionNotification.body = "Error creating configuration for network"
                UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.connect.failed", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                    
                })
                self.currentStatus = .error(.errorGettingConfiguration)
                Magic.EventBus.post(self.status)
                return
            }
            
            NEHotspotConfigurationManager.shared.apply(networkConfiguration) { (error) in
                // TODO: we have a slight issue here, even when its unable to join the network we get no error so it sends a success state
                if error != nil {
                    if NEHotspotConfigurationError(rawValue: (error! as NSError).code) == .alreadyAssociated {
                        print("Already connected to the network")
                        self.currentStatus = .connected
                        self.lastActiveMagicNetwork = ssid
                        Magic.EventBus.post(self.status)
                    } else {
                        connectionNotification.title = "Failed"
                        connectionNotification.subtitle = "Could not connect to network \(ssid)"
                        connectionNotification.body = "Error: \(error!.localizedDescription)"
                        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.connect.failed", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                            
                        })
                        self.currentStatus = .error(.errorConnectingToNetwork)
                        Magic.EventBus.post(self.status)
                    }
                } else {
                    if self.currentSSID() != ssid {
                        self.currentStatus = .error(.errorConnectingToNetwork)
                        Magic.EventBus.post(self.status)
                    } else {
                        if ud.bool(forKey: "magic.notification.connect") {
                            
                            connectionNotification.title = "Connected"
                            connectionNotification.body = "You are now connected to \(ssid)"
                            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.connect.success", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                                
                            })
                        }
                        self.currentStatus = .connected
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
            self.currentStatus = .error(.errorGettingConfiguration)
            Magic.EventBus.post(self.status)
        }
    }
    
    private func removeMagicConfig(_ ssid: String) {
        NEHotspotConfigurationManager.shared.removeConfiguration(forSSID: ssid)
        lastActiveMagicNetwork = nil
    }
    
    private func removeMagicConfigAndDisconnect(_ ssid: String) {
        removeMagicConfig(ssid)
        self.currentStatus = .disconnected
        Magic.EventBus.post(MagicStatus.disconnected)
    }
    
    fileprivate func setDisconnected() {
        //Don't disconnect from the network just set our status to disconnected
        self.currentStatus = .disconnected
        Magic.EventBus.post(self.status)
    }
    
    func disconnect() {
        if let network = activeNetwork  {
            let ud = UserDefaults.standard
            
            let hasLogoffStarted = NEHotspotHelper.logoff(network)
            NSLog("Has logoff started: \(hasLogoffStarted)")
            
            if ud.bool(forKey: "magic.notification.disconnect") {
                let connectionNotification = UNMutableNotificationContent()
                connectionNotification.title = "Disconnected"
                connectionNotification.body = "You are now disconnected from \(network.ssid)"
                UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "magic.disconnect.success", content: connectionNotification, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)), withCompletionHandler: {error in
                    
                })
            }
        }
        if currentSSID().hasPrefix("magic") || lastActiveMagicNetwork != nil {
            //                NEHotspotConfigurationManager.shared.removeConfiguration(forSSID: lastActiveMagicNetwork ?? currentSSID())
            lastActiveMagicNetwork = nil
        }
        self.currentStatus = .disconnected
        Magic.EventBus.post(self.status)
    }
    
    func generateEAPSettings(username: String, password: String) -> NEHotspotEAPSettings {
        let hotspotEAPSettings = NEHotspotEAPSettings()
        hotspotEAPSettings.username = username
        hotspotEAPSettings.password = password
        hotspotEAPSettings.isTLSClientCertificateRequired = true
        hotspotEAPSettings.supportedEAPTypes = [NEHotspotEAPSettings.EAPType.EAPTTLS.rawValue] as [NSNumber]
        hotspotEAPSettings.ttlsInnerAuthenticationType = .eapttlsInnerAuthenticationPAP
        hotspotEAPSettings.setTrustedServerCertificates([app_certificate!])
        return hotspotEAPSettings
    }
    
    func currentSSID() -> String {
        if let interfaces = CNCopySupportedInterfaces() {
            for interface in interfaces as! [CFString] {
                if let unsafeInterfaceData = CNCopyCurrentNetworkInfo(interface) {
                    let interfaceData = unsafeInterfaceData as Dictionary
                    return interfaceData[kCNNetworkInfoKeySSID] as! String
                }
            }
        }
        return ""
    }
}

fileprivate extension iOSMagicNetwork {
    
    func setupNetworkMonitor() {
        // Can we get the gateways uri/ip to use for this?
        var sock = sockaddr()
        sock.sa_len = UInt8(MemoryLayout<sockaddr>.size)
        sock.sa_family = sa_family_t(AF_INET)
        guard let ref = SCNetworkReachabilityCreateWithAddress(kCFAllocatorDefault, &sock) else {
            print("Failed to create Reachability")
            return
        }
        
        var context = SCNetworkReachabilityContext(version: 0, info: nil, retain: nil, release: nil, copyDescription: nil)
        
        guard SCNetworkReachabilitySetCallback(ref, { (reachability, flags, info) in
            print("Reachability Changed")
            print("Current SSID: \(Magic.Connectivity.shared.currentSSID())")
            print("Last Active Magic Node: \(Magic.Connectivity.shared.lastActiveMagicNetwork)")
            print("Is reachable? \(flags.contains(.reachable))")
            print("Is WWAN? \(flags.contains(.isWWAN))")
            // evidently we can't use self in callbacks for this function
            if !flags.contains(.reachable) || flags.contains(.isWWAN) {
                // When we are switching networks it first triggers with unreachable but with a ssid
                // if the ssid is empty than we actaully have been disconnected
                if Magic.Connectivity.shared.currentSSID().isEmpty && Magic.Connectivity.shared.lastActiveMagicNetwork != nil {
                    // The network state changed, maybe the internet went down or we moved out of range
                    // but we can't reach the internet so disconnect
                    Magic.Connectivity.shared.setDisconnected()
                    Magic.Connectivity.shared.removeMagicConfigAndDisconnect(Magic.Connectivity.shared.lastActiveMagicNetwork!)
                }
            } else if flags.contains(.reachable) {
                // if we are connected but not to a magic network, don't disconnect from that network but remove magic config
                if !Magic.Connectivity.shared.currentSSID().hasPrefix("magic") && Magic.Connectivity.shared.lastActiveMagicNetwork != nil {
                    Magic.Connectivity.shared.setDisconnected()
                    Magic.Connectivity.shared.removeMagicConfigAndDisconnect(Magic.Connectivity.shared.lastActiveMagicNetwork!)
                } else if Magic.Connectivity.shared.currentSSID().hasPrefix("magic") && Magic.Connectivity.shared.lastActiveMagicNetwork != nil && Magic.Connectivity.shared.currentSSID() != Magic.Connectivity.shared.lastActiveMagicNetwork {
                    // We connected to a new magic network, forget the old configuration
                    Magic.Connectivity.shared.removeMagicConfig(Magic.Connectivity.shared.lastActiveMagicNetwork!)
                    
                }
            }
        }, &context) else {
            print("Failed to set callback")
            return
        }
        // Only triggers in foreground currently
        guard SCNetworkReachabilitySetDispatchQueue(ref, .main) else {
            SCNetworkReachabilitySetCallback(ref, nil, nil)
            print("Failed to add to dispatch queue")
            return
        }
        
        print("Successfully registered network status monitor")
    }
}
#endif
