/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.networkstack.util;

import android.content.Context;
import android.net.LinkAddress;
import android.net.MacAddress;
import android.system.ErrnoException;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.net.module.util.DeviceConfigUtils;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

/**
 * Collection of utilities for the network stack.
 */
public class NetworkStackUtils {
    private static final String TAG = "NetworkStackUtils";

    /**
     * A list of captive portal detection specifications used in addition to the fallback URLs.
     * Each spec has the format url@@/@@statusCodeRegex@@/@@contentRegex. Specs are separated
     * by "@@,@@".
     */
    public static final String CAPTIVE_PORTAL_FALLBACK_PROBE_SPECS =
            "captive_portal_fallback_probe_specs";

    /**
     * A comma separated list of URLs used for captive portal detection in addition to the
     * fallback HTTP url associated with the CAPTIVE_PORTAL_FALLBACK_URL settings.
     */
    public static final String CAPTIVE_PORTAL_OTHER_FALLBACK_URLS =
            "captive_portal_other_fallback_urls";

    /**
     * A comma separated list of URLs used for captive portal detection in addition to the HTTP url
     * associated with the CAPTIVE_PORTAL_HTTP_URL settings.
     */
    public static final String CAPTIVE_PORTAL_OTHER_HTTP_URLS = "captive_portal_other_http_urls";

    /**
     * A comma separated list of URLs used for network validation. in addition to the HTTPS url
     * associated with the CAPTIVE_PORTAL_HTTPS_URL settings.
     */
    public static final String CAPTIVE_PORTAL_OTHER_HTTPS_URLS = "captive_portal_other_https_urls";

    /**
     * Which User-Agent string to use in the header of the captive portal detection probes.
     * The User-Agent field is unset when this setting has no value (HttpUrlConnection default).
     */
    public static final String CAPTIVE_PORTAL_USER_AGENT = "captive_portal_user_agent";

    /**
     * Whether to use HTTPS for network validation. This is enabled by default and the setting
     * needs to be set to 0 to disable it. This setting is a misnomer because captive portals
     * don't actually use HTTPS, but it's consistent with the other settings.
     */
    public static final String CAPTIVE_PORTAL_USE_HTTPS = "captive_portal_use_https";

    /**
     * The URL used for HTTPS captive portal detection upon a new connection.
     * A 204 response code from the server is used for validation.
     */
    public static final String CAPTIVE_PORTAL_HTTPS_URL = "captive_portal_https_url";

    /**
     * The URL used for HTTP captive portal detection upon a new connection.
     * A 204 response code from the server is used for validation.
     */
    public static final String CAPTIVE_PORTAL_HTTP_URL = "captive_portal_http_url";

    /**
     * The URL used for fallback HTTP captive portal detection when previous HTTP
     * and HTTPS captive portal detection attemps did not return a conclusive answer.
     */
    public static final String CAPTIVE_PORTAL_FALLBACK_URL = "captive_portal_fallback_url";

    /**
     * What to do when connecting a network that presents a captive portal.
     * Must be one of the CAPTIVE_PORTAL_MODE_* constants above.
     *
     * The default for this setting is CAPTIVE_PORTAL_MODE_PROMPT.
     */
    public static final String CAPTIVE_PORTAL_MODE = "captive_portal_mode";

    /**
     * Don't attempt to detect captive portals.
     */
    public static final int CAPTIVE_PORTAL_MODE_IGNORE = 0;

    /**
     * When detecting a captive portal, display a notification that
     * prompts the user to sign in.
     */
    public static final int CAPTIVE_PORTAL_MODE_PROMPT = 1;

    /**
     * When detecting a captive portal, immediately disconnect from the
     * network and do not reconnect to that network in the future.
     */
    public static final int CAPTIVE_PORTAL_MODE_AVOID = 2;

    /**
     * DNS probe timeout for network validation. Enough for 3 DNS queries 5 seconds apart.
     */
    public static final int DEFAULT_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT = 12500;

    /**
     * List of fallback probe specs to use for detecting captive portals. This is an alternative to
     * fallback URLs that provides more flexibility on detection rules. Empty, so unused by default.
     */
    public static final String[] DEFAULT_CAPTIVE_PORTAL_FALLBACK_PROBE_SPECS =
            new String[] {};

    /**
     * The default list of HTTP URLs to use for detecting captive portals.
     */
    public static final String[] DEFAULT_CAPTIVE_PORTAL_HTTP_URLS =
            new String [] {"http://connectivitycheck.gstatic.com/generate_204"};

    /**
     * The default list of HTTPS URLs for network validation, to use for confirming internet
     * connectivity.
     */
    public static final String[] DEFAULT_CAPTIVE_PORTAL_HTTPS_URLS =
            new String [] {"https://www.google.com/generate_204"};

    /**
     * @deprecated Considering boolean experiment flag is likely to cause misconfiguration
     *             particularly when NetworkStack module rolls back to previous version. It's
     *             much safer to determine whether or not to enable one specific experimental
     *             feature by comparing flag version with module version.
     */
    @Deprecated
    public static final String DHCP_INIT_REBOOT_ENABLED = "dhcp_init_reboot_enabled";

    /**
     * @deprecated See above explanation.
     */
    @Deprecated
    public static final String DHCP_RAPID_COMMIT_ENABLED = "dhcp_rapid_commit_enabled";

    /**
     * Disable dropping DHCP packets with IPv4 MF flag set.
     */
    public static final String DHCP_DISABLE_DROP_MF = "dhcp_disable_drop_mf";

    /**
     * Minimum module version at which to enable the DHCP INIT-REBOOT state.
     */
    public static final String DHCP_INIT_REBOOT_VERSION = "dhcp_init_reboot_version";

    /**
     * Minimum module version at which to enable the DHCP Rapid Commit option.
     */
    public static final String DHCP_RAPID_COMMIT_VERSION = "dhcp_rapid_commit_version";

    /**
     * Minimum module version at which to enable the IP address conflict detection feature.
     */
    public static final String DHCP_IP_CONFLICT_DETECT_VERSION = "dhcp_ip_conflict_detect_version";

    /**
     * Minimum module version at which to enable the IPv6-Only preferred option.
     */
    public static final String DHCP_IPV6_ONLY_PREFERRED_VERSION =
            "dhcp_ipv6_only_preferred_version";

    /**
     * Minimum module version at which to enable slow DHCP retransmission approach in renew/rebind
     * state suggested in RFC2131 section 4.4.5.
     */
    public static final String DHCP_SLOW_RETRANSMISSION_VERSION =
            "dhcp_slow_retransmission_version";

    /**
     * Experiment flag to enable considering DNS probes returning private IP addresses as failed
     * when attempting to detect captive portals.
     *
     * This flag is enabled if !=0 and less than the module APK version.
     */
    public static final String DNS_PROBE_PRIVATE_IP_NO_INTERNET_VERSION =
            "dns_probe_private_ip_no_internet";

    /**
     * Experiment flag to enable validation metrics sent by NetworkMonitor.
     *
     * Metrics are sent by default. They can be disabled by setting the flag to a number greater
     * than the APK version (for example 999999999).
     * @see DeviceConfigUtils#isFeatureEnabled(Context, String, String, boolean)
     */
    public static final String VALIDATION_METRICS_VERSION = "validation_metrics_version";

    /**
     * Experiment flag to enable sending gratuitous multicast unsolicited Neighbor Advertisements
     * to propagate new assigned IPv6 GUA as quickly as possible.
     */
    public static final String IPCLIENT_GRATUITOUS_NA_VERSION = "ipclient_gratuitous_na_version";

    /**
     * Experiment flag to send multicast NS from the global IPv6 GUA to the solicited-node
     * multicast address based on the default router's IPv6 link-local address, which helps
     * flush the first-hop routers' neighbor cache entry for the global IPv6 GUA.
     */
    public static final String IPCLIENT_MULTICAST_NS_VERSION = "ipclient_multicast_ns_version";

    /**
     * Experiment flag to enable sending Gratuitous APR and Gratuitous Neighbor Advertisement for
     * all assigned IPv4 and IPv6 GUAs after completing L2 roaming.
     */
    public static final String IPCLIENT_GARP_NA_ROAMING_VERSION =
            "ipclient_garp_na_roaming_version";

    /**
     * Experiment flag to enable parsing netlink events from kernel directly instead from netd aidl
     * interface.
     */
    public static final String IPCLIENT_PARSE_NETLINK_EVENTS_VERSION =
            "ipclient_parse_netlink_events_version";

    /**
     * Experiment flag to disable accept_ra parameter when IPv6 provisioning loss happens due to
     * the default route has gone.
     */
    public static final String IPCLIENT_DISABLE_ACCEPT_RA_VERSION = "ipclient_disable_accept_ra";

    /**
     * Experiment flag to enable "mcast_resolicit" neighbor parameter in IpReachabilityMonitor,
     * set it to 3 by default.
     */
    public static final String IP_REACHABILITY_MCAST_RESOLICIT_VERSION =
            "ip_reachability_mcast_resolicit_version";

    static {
        System.loadLibrary("networkstackutilsjni");
    }

    /**
     * Convert IPv6 multicast address to ethernet multicast address in network order.
     */
    public static MacAddress ipv6MulticastToEthernetMulticast(@NonNull final Inet6Address addr) {
        final byte[] etherMulticast = new byte[6];
        final byte[] ipv6Multicast = addr.getAddress();
        etherMulticast[0] = (byte) 0x33;
        etherMulticast[1] = (byte) 0x33;
        etherMulticast[2] = ipv6Multicast[12];
        etherMulticast[3] = ipv6Multicast[13];
        etherMulticast[4] = ipv6Multicast[14];
        etherMulticast[5] = ipv6Multicast[15];
        return MacAddress.fromBytes(etherMulticast);
    }

    /**
     * Convert IPv6 unicast or anycast address to solicited node multicast address
     * per RFC4291 section 2.7.1.
     */
    @Nullable
    public static Inet6Address ipv6AddressToSolicitedNodeMulticast(
            @NonNull final Inet6Address addr) {
        final byte[] address = new byte[16];
        address[0] = (byte) 0xFF;
        address[1] = (byte) 0x02;
        address[11] = (byte) 0x01;
        address[12] = (byte) 0xFF;
        address[13] = addr.getAddress()[13];
        address[14] = addr.getAddress()[14];
        address[15] = addr.getAddress()[15];
        try {
            return (Inet6Address) InetAddress.getByAddress(address);
        } catch (UnknownHostException e) {
            Log.e(TAG, "Invalid host IP address " + addr.getHostAddress(), e);
            return null;
        }
    }

    /**
     * Check whether a link address is IPv6 global preferred unicast address.
     */
    public static boolean isIPv6GUA(@NonNull final LinkAddress address) {
        return address.isIpv6() && address.isGlobalPreferred();
    }

    /**
     * Attaches a socket filter that accepts DHCP packets to the given socket.
     */
    public static native void attachDhcpFilter(FileDescriptor fd, boolean dropMF)
            throws ErrnoException;

    /**
     * Attaches a socket filter that accepts ICMPv6 router advertisements to the given socket.
     * @param fd the socket's {@link FileDescriptor}.
     * @param packetType the hardware address type, one of ARPHRD_*.
     */
    public static native void attachRaFilter(FileDescriptor fd, int packetType)
            throws SocketException;

    /**
     * Attaches a socket filter that accepts L2-L4 signaling traffic required for IP connectivity.
     *
     * This includes: all ARP, ICMPv6 RS/RA/NS/NA messages, and DHCPv4 exchanges.
     *
     * @param fd the socket's {@link FileDescriptor}.
     * @param packetType the hardware address type, one of ARPHRD_*.
     */
    public static native void attachControlPacketFilter(FileDescriptor fd, int packetType)
            throws SocketException;

    /**
     * Add an entry into the ARP cache.
     */
    public static void addArpEntry(Inet4Address ipv4Addr, android.net.MacAddress ethAddr,
            String ifname, FileDescriptor fd) throws IOException {
        addArpEntry(ethAddr.toByteArray(), ipv4Addr.getAddress(), ifname, fd);
    }

    private static native void addArpEntry(byte[] ethAddr, byte[] netAddr, String ifname,
            FileDescriptor fd) throws IOException;

}