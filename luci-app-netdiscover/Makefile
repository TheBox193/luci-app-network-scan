include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-netdiscover
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

LUCI_TITLE:=LuCI Network Discovery & Scan Tool
LUCI_DESCRIPTION:=Unified, read-only network discovery view correlating ARP, DHCP, Wi-Fi, and optional probes.
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+luci-base +luci-lib-jsonc +luci-lib-nixio +rpcd +rpcd-mod-luci +nmap +arp-scan +iw +ip-full +ip-bridge

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
