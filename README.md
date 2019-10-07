# magic.swift

Swift library for authentication to the Magic Network

__This is an alpha version and users should be aware that breaking changes may happen in each update.__

In order to utilize this library you will need to [have a router setup](https://magic-network.github.io/magic-agent/provider/gateway/quick-start/router-setup.html) and a
[magic gateway](https://magic-network.github.io/magic-agent/provider/gateway/quick-start/gateway-server-setup.html) running to complete the authenication

## iOS issues

There is currently no way to scan for networks manually, or get a list of nearby wifi networks without an entitlement and manually opening up the settings menu. For this reason finding and passing along the ssid of the magic network is not as easy as it is on other platforms.
