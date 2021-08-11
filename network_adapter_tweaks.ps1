Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Adaptive Inter-Frame Spacing' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'ARP Offload' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Enable PME' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Energy Efficient Ethernet' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Flow Control' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Interrupt Moderation Rate' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Interrupt Moderation' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'IPv4 Checksum Offload' -RegistryValue 3
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Jumbo Packet' -RegistryValue 1514
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Jumbo Packet' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Large Send Offload V2 (IPv4)' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Large Send Offload V2 (IPv6)' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Packet Priority & VLAN' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Protocol NS Offload' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Receive Buffers' -RegistryValue 2048
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Receive Side Scaling' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Reduce Speed On Power Down' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'System Idle Power Saver' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'TCP Checksum Offload (IPv4)' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'TCP Checksum Offload (IPv6)' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Transmit Buffers' -RegistryValue 2048
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'UDP Checksum Offload (IPv4)' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'UDP Checksum Offload (IPv6)' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Ultra Low Power Mode' -RegistryValue 0
Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Green Ethernet' -RegistryValue 0
Set-NetAdapterBinding -Name '*' -DisplayName 'Microsoft LLDP Protocol Driver' -Enabled 0
Set-NetAdapterBinding -Name '*' -DisplayName 'Link-Layer Topology Discovery Responder' -Enabled 0
Set-NetAdapterBinding -Name '*' -DisplayName 'Link-Layer Topology Discovery Mapper I/O Driver' -Enabled 0
Set-NetAdapterBinding -Name '*' -DisplayName 'QoS Packet Scheduler' -Enabled 0
Set-NetAdapterBinding -Name '*' -DisplayName 'Hyper-V Extensible Virtual Switch' -Enabled 0
Set-NetIPinterface -EcnMarking 1
Set-NetTCPSetting -SettingName Internet -EcnCapability enabled
Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal normal
Set-NetTCPSetting -SettingName Internet -ScalingHeuristics disabled
Set-NetTCPSetting -SettingName Internet -Timestamps disabled
Set-NetTCPSetting -SettingName Internet -MaxSynRetransmissions 2
Set-NetTCPSetting -SettingName Internet -InitialCongestionWindow 10
Set-NetOffloadGlobalSetting -ReceiveSideScaling disabled
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled
Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled
Set-NetOffloadGlobalSetting -Chimney disabled
Set-NetOffloadGlobalSetting -TaskOffload disabled
Disable-NetAdapterIPsecOffload -Name '*'
Disable-NetAdapterPowerManagement -Name '*'
Disable-NetAdapterQos -Name '*'
Disable-NetAdapterChecksumOffload -Name '*'
Disable-NetAdapterLso -Name '*'
Disable-NetAdapterRsc -Name '*'
Enable-NetAdapterRss -Name '*'
<# Delayed ACKs are bad; Nagle's algorithm alone is not. https://archive.is/6HhtH #>
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*' -Name TcpAckFrequency -Value 2
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*' -Name TcpDelAckTicks -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*' -Name TCPNoDelay -Value 0
