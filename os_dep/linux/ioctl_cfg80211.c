/******************************************************************************
 *
 * Copyright(c) 2007 - 2012 Realtek Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 *
 ******************************************************************************/
#define  _IOCTL_CFG80211_C_

#include <drv_types.h>
#include <hal_data.h>

#ifdef CONFIG_IOCTL_CFG80211

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
#define STATION_INFO_SIGNAL		BIT(NL80211_STA_INFO_SIGNAL)
#define STATION_INFO_TX_BITRATE		BIT(NL80211_STA_INFO_TX_BITRATE)
#define STATION_INFO_RX_PACKETS		BIT(NL80211_STA_INFO_RX_PACKETS)
#define STATION_INFO_TX_PACKETS		BIT(NL80211_STA_INFO_TX_PACKETS)
#define STATION_INFO_ASSOC_REQ_IES	0
#endif /* Linux kernel >= 4.0.0 */

#include <rtw_wifi_regd.h>

#define RTW_MAX_MGMT_TX_CNT (8)
#define RTW_MAX_MGMT_TX_MS_GAS (500)

#define RTW_SCAN_IE_LEN_MAX      2304
#define RTW_MAX_REMAIN_ON_CHANNEL_DURATION 5000 /* ms */
#define RTW_MAX_NUM_PMKIDS 4

#define RTW_CH_MAX_2G_CHANNEL               14      /* Max channel in 2G band */

#ifdef CONFIG_WAPI_SUPPORT

#ifndef WLAN_CIPHER_SUITE_SMS4
#define WLAN_CIPHER_SUITE_SMS4          0x00147201
#endif

#ifndef WLAN_AKM_SUITE_WAPI_PSK
#define WLAN_AKM_SUITE_WAPI_PSK         0x000FAC04
#endif

#ifndef WLAN_AKM_SUITE_WAPI_CERT
#define WLAN_AKM_SUITE_WAPI_CERT        0x000FAC12
#endif

#ifndef NL80211_WAPI_VERSION_1
#define NL80211_WAPI_VERSION_1          (1 << 2)
#endif

#endif /* CONFIG_WAPI_SUPPORT */


static const u32 rtw_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
#ifdef CONFIG_WAPI_SUPPORT
	WLAN_CIPHER_SUITE_SMS4,
#endif /* CONFIG_WAPI_SUPPORT */
#ifdef CONFIG_IEEE80211W
	WLAN_CIPHER_SUITE_AES_CMAC,
#endif /* CONFIG_IEEE80211W */
};

#define RATETAB_ENT(_rate, _rateid, _flags) \
	{								\
		.bitrate	= (_rate),				\
		.hw_value	= (_rateid),				\
		.flags		= (_flags),				\
	}

#define CHAN2G(_channel, _freq, _flags) {			\
		.band			= IEEE80211_BAND_2GHZ,		\
		.center_freq		= (_freq),			\
		.hw_value		= (_channel),			\
		.flags			= (_flags),			\
		.max_antenna_gain	= 0,				\
		.max_power		= 30,				\
	}

#define CHAN5G(_channel, _flags) {				\
		.band			= IEEE80211_BAND_5GHZ,		\
		.center_freq		= 5000 + (5 * (_channel)),	\
		.hw_value		= (_channel),			\
		.flags			= (_flags),			\
		.max_antenna_gain	= 0,				\
		.max_power		= 30,				\
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0))
/* if wowlan is not supported, kernel generate a disconnect at each suspend
 * cf: /net/wireless/sysfs.c, so register a stub wowlan.
 * Moreover wowlan has to be enabled via a the nl80211_set_wowlan callback.
 * (from user space, e.g. iw phy0 wowlan enable)
 */
static const struct wiphy_wowlan_support wowlan_stub = {
	.flags = WIPHY_WOWLAN_ANY,
	.n_patterns = 0,
	.pattern_max_len = 0,
	.pattern_min_len = 0,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	.max_pkt_offset = 0,
#endif
};
#endif

static struct ieee80211_rate rtw_rates[] = {
	RATETAB_ENT(10,  0x1,   0),
	RATETAB_ENT(20,  0x2,   0),
	RATETAB_ENT(55,  0x4,   0),
	RATETAB_ENT(110, 0x8,   0),
	RATETAB_ENT(60,  0x10,  0),
	RATETAB_ENT(90,  0x20,  0),
	RATETAB_ENT(120, 0x40,  0),
	RATETAB_ENT(180, 0x80,  0),
	RATETAB_ENT(240, 0x100, 0),
	RATETAB_ENT(360, 0x200, 0),
	RATETAB_ENT(480, 0x400, 0),
	RATETAB_ENT(540, 0x800, 0),
};

#define rtw_a_rates		(rtw_rates + 4)
#define RTW_A_RATES_NUM	8
#define rtw_g_rates		(rtw_rates + 0)
#define RTW_G_RATES_NUM	12

#define RTW_2G_CHANNELS_NUM 14
#define RTW_5G_CHANNELS_NUM 41

static struct ieee80211_channel rtw_2ghz_channels[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

static struct ieee80211_channel rtw_5ghz_a_channels[] = {
	CHAN5G(34, 0),		CHAN5G(36, 0),
	CHAN5G(38, 0),		CHAN5G(40, 0),
	CHAN5G(42, 0),		CHAN5G(44, 0),
	CHAN5G(46, 0),		CHAN5G(48, 0),
	CHAN5G(52, 0),		CHAN5G(56, 0),
	CHAN5G(58, 0),		CHAN5G(60, 0),
	CHAN5G(62, 0),		CHAN5G(64, 0),
	CHAN5G(100, 0),		CHAN5G(104, 0),
	CHAN5G(108, 0),		CHAN5G(112, 0),
	CHAN5G(116, 0),		CHAN5G(120, 0),
	CHAN5G(124, 0),		CHAN5G(128, 0),
	CHAN5G(132, 0),		CHAN5G(136, 0),
	CHAN5G(140, 0),		CHAN5G(144, 0),	CHAN5G(149, 0),
	CHAN5G(153, 0),		CHAN5G(157, 0),
	CHAN5G(161, 0),		CHAN5G(165, 0), CHAN5G(169, 0),
	CHAN5G(184, 0),		CHAN5G(188, 0),
	CHAN5G(192, 0),		CHAN5G(196, 0),
	CHAN5G(200, 0),		CHAN5G(204, 0),
	CHAN5G(208, 0),		CHAN5G(212, 0),
	CHAN5G(216, 0),
};


void rtw_2g_channels_init(struct ieee80211_channel *channels)
{
	_rtw_memcpy((void *)channels, (void *)rtw_2ghz_channels,
		sizeof(struct ieee80211_channel) * RTW_2G_CHANNELS_NUM
	);
}

void rtw_5g_channels_init(struct ieee80211_channel *channels)
{
	_rtw_memcpy((void *)channels, (void *)rtw_5ghz_a_channels,
		sizeof(struct ieee80211_channel) * RTW_5G_CHANNELS_NUM
	);
}

void rtw_2g_rates_init(struct ieee80211_rate *rates)
{
	_rtw_memcpy(rates, rtw_g_rates,
		sizeof(struct ieee80211_rate) * RTW_G_RATES_NUM
	);
}

void rtw_5g_rates_init(struct ieee80211_rate *rates)
{
	_rtw_memcpy(rates, rtw_a_rates,
		sizeof(struct ieee80211_rate) * RTW_A_RATES_NUM
	);
}

struct ieee80211_supported_band *rtw_spt_band_alloc(
	enum ieee80211_band band
)
{
	struct ieee80211_supported_band *spt_band = NULL;
	int n_channels, n_bitrates;

	if (band == IEEE80211_BAND_2GHZ) {
		n_channels = RTW_2G_CHANNELS_NUM;
		n_bitrates = RTW_G_RATES_NUM;
	} else if (band == IEEE80211_BAND_5GHZ) {
		n_channels = RTW_5G_CHANNELS_NUM;
		n_bitrates = RTW_A_RATES_NUM;
	} else
		goto exit;

	spt_band = (struct ieee80211_supported_band *)rtw_zmalloc(
		sizeof(struct ieee80211_supported_band)
		+ sizeof(struct ieee80211_channel) * n_channels
		+ sizeof(struct ieee80211_rate) * n_bitrates
	);
	if (!spt_band)
		goto exit;

	spt_band->channels = (struct ieee80211_channel *)(((u8 *)spt_band) + sizeof(struct ieee80211_supported_band));
	spt_band->bitrates = (struct ieee80211_rate *)(((u8 *)spt_band->channels) + sizeof(struct ieee80211_channel) * n_channels);
	spt_band->band = band;
	spt_band->n_channels = n_channels;
	spt_band->n_bitrates = n_bitrates;

	if (band == IEEE80211_BAND_2GHZ) {
		rtw_2g_channels_init(spt_band->channels);
		rtw_2g_rates_init(spt_band->bitrates);
	} else if (band == IEEE80211_BAND_5GHZ) {
		rtw_5g_channels_init(spt_band->channels);
		rtw_5g_rates_init(spt_band->bitrates);
	}

	/* spt_band.ht_cap */

exit:

	return spt_band;
}

void rtw_spt_band_free(struct ieee80211_supported_band *spt_band)
{
	u32 size = 0;

	if (!spt_band)
		return;

	if (spt_band->band == IEEE80211_BAND_2GHZ) {
		size = sizeof(struct ieee80211_supported_band)
			+ sizeof(struct ieee80211_channel) * RTW_2G_CHANNELS_NUM
			+ sizeof(struct ieee80211_rate) * RTW_G_RATES_NUM;
	} else if (spt_band->band == IEEE80211_BAND_5GHZ) {
		size = sizeof(struct ieee80211_supported_band)
			+ sizeof(struct ieee80211_channel) * RTW_5G_CHANNELS_NUM
			+ sizeof(struct ieee80211_rate) * RTW_A_RATES_NUM;
	} else {

	}
	rtw_mfree((u8 *)spt_band, size);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
static const struct ieee80211_txrx_stypes
	rtw_cfg80211_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_ADHOC] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_STATION] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_AP] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_AP_VLAN] = {
		/* copy AP */
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_P2P_CLIENT] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_P2P_GO] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
		BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
		BIT(IEEE80211_STYPE_DISASSOC >> 4) |
		BIT(IEEE80211_STYPE_AUTH >> 4) |
		BIT(IEEE80211_STYPE_DEAUTH >> 4) |
		BIT(IEEE80211_STYPE_ACTION >> 4)
	},
};
#endif

static u64 rtw_get_systime_us(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39))
	struct timespec ts;
	get_monotonic_boottime(&ts);
	return ((u64)ts.tv_sec * 1000000) + ts.tv_nsec / 1000;
#else
	struct timeval tv;
	do_gettimeofday(&tv);
	return ((u64)tv.tv_sec * 1000000) + tv.tv_usec;
#endif
}

#define MAX_BSSINFO_LEN 1000
struct cfg80211_bss *rtw_cfg80211_inform_bss(_adapter *padapter, struct wlan_network *pnetwork)
{
	struct ieee80211_channel *notify_channel;
	struct cfg80211_bss *bss = NULL;
	/* struct ieee80211_supported_band *band;       */
	u16 channel;
	u32 freq;
	u64 notify_timestamp;
	u16 notify_capability;
	u16 notify_interval;
	u8 *notify_ie;
	size_t notify_ielen;
	s32 notify_signal;
	/* u8 buf[MAX_BSSINFO_LEN]; */

	u8 *pbuf;
	size_t buf_size = MAX_BSSINFO_LEN;
	size_t len, bssinf_len = 0;
	struct rtw_ieee80211_hdr *pwlanhdr;
	unsigned short *fctrl;
	u8	bc_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	struct wireless_dev *wdev = padapter->rtw_wdev;
	struct wiphy *wiphy = wdev->wiphy;
	struct mlme_priv *pmlmepriv = &(padapter->mlmepriv);

	pbuf = rtw_zmalloc(buf_size);
	if (pbuf == NULL) {
		RTW_INFO("%s pbuf allocate failed  !!\n", __FUNCTION__);
		return bss;
	}

	/* RTW_INFO("%s\n", __func__); */

	bssinf_len = pnetwork->network.IELength + sizeof(struct rtw_ieee80211_hdr_3addr);
	if (bssinf_len > buf_size) {
		RTW_INFO("%s IE Length too long > %zu byte\n", __FUNCTION__, buf_size);
		goto exit;
	}

#ifndef CONFIG_WAPI_SUPPORT
	{
		u16 wapi_len = 0;

		if (rtw_get_wapi_ie(pnetwork->network.IEs, pnetwork->network.IELength, NULL, &wapi_len) > 0) {
			if (wapi_len > 0) {
				RTW_INFO("%s, no support wapi!\n", __FUNCTION__);
				goto exit;
			}
		}
	}
#endif /* !CONFIG_WAPI_SUPPORT */

	/* To reduce PBC Overlap rate */
	/* _enter_critical_bh(&pwdev_priv->scan_req_lock, &irqL); */
	if (adapter_wdev_data(padapter)->scan_request != NULL) {
		u8 *psr = NULL, sr = 0;
		NDIS_802_11_SSID *pssid = &pnetwork->network.Ssid;
		struct cfg80211_scan_request *request = adapter_wdev_data(padapter)->scan_request;
		struct cfg80211_ssid *ssids = request->ssids;
		u32 wpsielen = 0;
		u8 *wpsie = NULL;

		wpsie = rtw_get_wps_ie(pnetwork->network.IEs + _FIXED_IE_LENGTH_, pnetwork->network.IELength - _FIXED_IE_LENGTH_, NULL, &wpsielen);

		if (wpsie && wpsielen > 0)
			psr = rtw_get_wps_attr_content(wpsie,  wpsielen, WPS_ATTR_SELECTED_REGISTRAR, (u8 *)(&sr), NULL);

		if (sr != 0) {
			if (request->n_ssids == 1 && request->n_channels == 1) { /* it means under processing WPS */
				RTW_INFO("ssid=%s, len=%d\n", pssid->Ssid, pssid->SsidLength);

				if (ssids[0].ssid_len == 0) {
				} else if (pssid->SsidLength == ssids[0].ssid_len &&
					_rtw_memcmp(pssid->Ssid, ssids[0].ssid, ssids[0].ssid_len))
					RTW_INFO("%s, got sr and ssid match!\n", __func__);
				else {
					if (psr != NULL)
						*psr = 0; /* clear sr */

#if 0
					WLAN_BSSID_EX  *pselect_network = &pnetwork->network;
					struct cfg80211_bss *pselect_bss = NULL;
					struct ieee80211_channel *notify_channel = NULL;
					u32 freq;

					RTW_INFO("%s, got sr, but ssid mismatch, to remove this bss\n", __func__);

					freq = rtw_ch2freq(pselect_network->Configuration.DSConfig);
					notify_channel = ieee80211_get_channel(wiphy, freq);
					pselect_bss = cfg80211_get_bss(wiphy, NULL/*notify_channel*/,
						pselect_network->MacAddress, pselect_network->Ssid.Ssid,
						pselect_network->Ssid.SsidLength, 0/*WLAN_CAPABILITY_ESS*/,
						0/*WLAN_CAPABILITY_ESS*/);

					if (pselect_bss) {
						RTW_INFO("%s, got bss for cfg80211 for unlinking bss\n", __func__);

						cfg80211_unlink_bss(wiphy, pselect_bss);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
						cfg80211_put_bss(wiphy, pselect_bss);
#else
						cfg80211_put_bss(pselect_bss);
#endif

					}

					goto exit;
#endif
				}
			}
		}
	}
	/* _exit_critical_bh(&pwdev_priv->scan_req_lock, &irqL); */


	channel = pnetwork->network.Configuration.DSConfig;
	freq = rtw_ch2freq(channel);
	notify_channel = ieee80211_get_channel(wiphy, freq);

	if (0)
		notify_timestamp = le64_to_cpu(*(u64 *)rtw_get_timestampe_from_ie(pnetwork->network.IEs));
	else
		notify_timestamp = rtw_get_systime_us();

	notify_interval = le16_to_cpu(*(u16 *)rtw_get_beacon_interval_from_ie(pnetwork->network.IEs));
	notify_capability = le16_to_cpu(*(u16 *)rtw_get_capability_from_ie(pnetwork->network.IEs));

	notify_ie = pnetwork->network.IEs + _FIXED_IE_LENGTH_;
	notify_ielen = pnetwork->network.IELength - _FIXED_IE_LENGTH_;

	/* We've set wiphy's signal_type as CFG80211_SIGNAL_TYPE_MBM: signal strength in mBm (100*dBm) */
	if (check_fwstate(pmlmepriv, _FW_LINKED) == _TRUE &&
		is_same_network(&pmlmepriv->cur_network.network, &pnetwork->network, 0)) {
		notify_signal = 100 * translate_percentage_to_dbm(padapter->recvpriv.signal_strength); /* dbm */
	} else {
		notify_signal = 100 * translate_percentage_to_dbm(pnetwork->network.PhyInfo.SignalStrength); /* dbm */
	}

#if 0
	RTW_INFO("bssid: "MAC_FMT"\n", MAC_ARG(pnetwork->network.MacAddress));
	RTW_INFO("Channel: %d(%d)\n", channel, freq);
	RTW_INFO("Capability: %X\n", notify_capability);
	RTW_INFO("Beacon interval: %d\n", notify_interval);
	RTW_INFO("Signal: %d\n", notify_signal);
	RTW_INFO("notify_timestamp: %llu\n", notify_timestamp);
#endif

	/* pbuf = buf; */

	pwlanhdr = (struct rtw_ieee80211_hdr *)pbuf;
	fctrl = &(pwlanhdr->frame_ctl);
	*(fctrl) = 0;

	SetSeqNum(pwlanhdr, 0/*pmlmeext->mgnt_seq*/);
	/* pmlmeext->mgnt_seq++; */

	if (pnetwork->network.Reserved[0] == 1) { /* WIFI_BEACON */
		_rtw_memcpy(pwlanhdr->addr1, bc_addr, ETH_ALEN);
		SetFrameSubType(pbuf, WIFI_BEACON);
	} else {
		_rtw_memcpy(pwlanhdr->addr1, adapter_mac_addr(padapter), ETH_ALEN);
		SetFrameSubType(pbuf, WIFI_PROBERSP);
	}

	_rtw_memcpy(pwlanhdr->addr2, pnetwork->network.MacAddress, ETH_ALEN);
	_rtw_memcpy(pwlanhdr->addr3, pnetwork->network.MacAddress, ETH_ALEN);


	/* pbuf += sizeof(struct rtw_ieee80211_hdr_3addr); */
	len = sizeof(struct rtw_ieee80211_hdr_3addr);
	_rtw_memcpy((pbuf + len), pnetwork->network.IEs, pnetwork->network.IELength);
	*((u64 *)(pbuf + len)) = cpu_to_le64(notify_timestamp);

	len += pnetwork->network.IELength;

	#if defined(CONFIG_P2P) && 0
	if(rtw_get_p2p_ie(pnetwork->network.IEs+12, pnetwork->network.IELength-12, NULL, NULL))
		RTW_INFO("%s, got p2p_ie\n", __func__);
	#endif

#if 1
	bss = cfg80211_inform_bss_frame(wiphy, notify_channel, (struct ieee80211_mgmt *)pbuf,
					len, notify_signal, GFP_ATOMIC);
#else

	bss = cfg80211_inform_bss(wiphy, notify_channel, (const u8 *)pnetwork->network.MacAddress,
		notify_timestamp, notify_capability, notify_interval, notify_ie,
		notify_ielen, notify_signal, GFP_ATOMIC/*GFP_KERNEL*/);
#endif

	if (unlikely(!bss)) {
		RTW_INFO(FUNC_ADPT_FMT" bss NULL\n", FUNC_ADPT_ARG(padapter));
		goto exit;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38))
#ifndef COMPAT_KERNEL_RELEASE
	/* patch for cfg80211, update beacon ies to information_elements */
	if (pnetwork->network.Reserved[0] == 1) { /* WIFI_BEACON */

		if (bss->len_information_elements != bss->len_beacon_ies) {
			bss->information_elements = bss->beacon_ies;
			bss->len_information_elements =  bss->len_beacon_ies;
		}
	}
#endif /* COMPAT_KERNEL_RELEASE */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) */

#if 0
	{
		if (bss->information_elements == bss->proberesp_ies) {
			if (bss->len_information_elements !=  bss->len_proberesp_ies)
				RTW_INFO("error!, len_information_elements != bss->len_proberesp_ies\n");
		} else if (bss->len_information_elements <  bss->len_beacon_ies) {
			bss->information_elements = bss->beacon_ies;
			bss->len_information_elements =  bss->len_beacon_ies;
		}
	}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	cfg80211_put_bss(wiphy, bss);
#else
	cfg80211_put_bss(bss);
#endif

exit:
	if (pbuf)
		rtw_mfree(pbuf, buf_size);
	return bss;

}

/*
	Check the given bss is valid by kernel API cfg80211_get_bss()
	@padapter : the given adapter

	return _TRUE if bss is valid,  _FALSE for not found.
*/
int rtw_cfg80211_check_bss(_adapter *padapter)
{
	WLAN_BSSID_EX  *pnetwork = &(padapter->mlmeextpriv.mlmext_info.network);
	struct cfg80211_bss *bss = NULL;
	struct ieee80211_channel *notify_channel = NULL;
	u32 freq;

	if (!(pnetwork) || !(padapter->rtw_wdev))
		return _FALSE;

	freq = rtw_ch2freq(pnetwork->Configuration.DSConfig);
	notify_channel = ieee80211_get_channel(padapter->rtw_wdev->wiphy, freq);
	bss = cfg80211_get_bss(padapter->rtw_wdev->wiphy, notify_channel,
			pnetwork->MacAddress, pnetwork->Ssid.Ssid,
			pnetwork->Ssid.SsidLength,
			WLAN_CAPABILITY_ESS, WLAN_CAPABILITY_ESS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	cfg80211_put_bss(padapter->rtw_wdev->wiphy, bss);
#else
	cfg80211_put_bss(bss);
#endif

	return bss != NULL;
}

void rtw_cfg80211_ibss_indicate_connect(_adapter *padapter)
{
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct wlan_network  *cur_network = &(pmlmepriv->cur_network);
	struct wireless_dev *pwdev = padapter->rtw_wdev;
	struct cfg80211_bss *bss = NULL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
	struct wiphy *wiphy = pwdev->wiphy;
	int freq = 2412;
	struct ieee80211_channel *notify_channel;
#endif

	RTW_INFO(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG(padapter));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
	freq = rtw_ch2freq(cur_network->network.Configuration.DSConfig);

	if (0)
		RTW_INFO("chan: %d, freq: %d\n", cur_network->network.Configuration.DSConfig, freq);
#endif

	if (pwdev->iftype != NL80211_IFTYPE_ADHOC)
		return;

	if (!rtw_cfg80211_check_bss(padapter)) {
		WLAN_BSSID_EX  *pnetwork = &(padapter->mlmeextpriv.mlmext_info.network);
		struct wlan_network *scanned = pmlmepriv->cur_network_scanned;

		if (check_fwstate(pmlmepriv, WIFI_ADHOC_MASTER_STATE) == _TRUE) {

			_rtw_memcpy(&cur_network->network, pnetwork, sizeof(WLAN_BSSID_EX));
			if (cur_network) {
				if (!rtw_cfg80211_inform_bss(padapter, cur_network))
					RTW_INFO(FUNC_ADPT_FMT" inform fail !!\n", FUNC_ADPT_ARG(padapter));
				else
					RTW_INFO(FUNC_ADPT_FMT" inform success !!\n", FUNC_ADPT_ARG(padapter));
			} else {
				RTW_INFO("cur_network is not exist!!!\n");
				return ;
			}
		} else {
			if (scanned == NULL)
				rtw_warn_on(1);

			if (_rtw_memcmp(&(scanned->network.Ssid), &(pnetwork->Ssid), sizeof(NDIS_802_11_SSID)) == _TRUE
				&& _rtw_memcmp(scanned->network.MacAddress, pnetwork->MacAddress, sizeof(NDIS_802_11_MAC_ADDRESS)) == _TRUE
			) {
				if (!rtw_cfg80211_inform_bss(padapter, scanned))
					RTW_INFO(FUNC_ADPT_FMT" inform fail !!\n", FUNC_ADPT_ARG(padapter));
				else {
					/* RTW_INFO(FUNC_ADPT_FMT" inform success !!\n", FUNC_ADPT_ARG(padapter)); */
				}
			} else {
				RTW_INFO("scanned & pnetwork compare fail\n");
				rtw_warn_on(1);
			}
		}

		if (!rtw_cfg80211_check_bss(padapter))
			RTW_PRINT(FUNC_ADPT_FMT" BSS not found !!\n", FUNC_ADPT_ARG(padapter));
	}
	/* notify cfg80211 that device joined an IBSS */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
	notify_channel = ieee80211_get_channel(wiphy, freq);
	cfg80211_ibss_joined(padapter->pnetdev, cur_network->network.MacAddress, notify_channel, GFP_ATOMIC);
#else
	cfg80211_ibss_joined(padapter->pnetdev, cur_network->network.MacAddress, GFP_ATOMIC);
#endif
}

void rtw_cfg80211_indicate_connect(_adapter *padapter)
{
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct wlan_network  *cur_network = &(pmlmepriv->cur_network);
	struct wireless_dev *pwdev = padapter->rtw_wdev;
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &(padapter->wdinfo);
#endif
	struct cfg80211_bss *bss = NULL;

	RTW_INFO(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG(padapter));
	if (pwdev->iftype != NL80211_IFTYPE_STATION
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
		&& pwdev->iftype != NL80211_IFTYPE_P2P_CLIENT
		#endif
	)
		return;

	if (check_fwstate(pmlmepriv, WIFI_AP_STATE) == _TRUE)
		return;

#ifdef CONFIG_P2P
	if (pwdinfo->driver_interface == DRIVER_CFG80211) {
		if (!rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE)) {
			rtw_p2p_set_pre_state(pwdinfo, rtw_p2p_state(pwdinfo));
			rtw_p2p_set_role(pwdinfo, P2P_ROLE_CLIENT);
			rtw_p2p_set_state(pwdinfo, P2P_STATE_GONEGO_OK);
			RTW_INFO("%s, role=%d, p2p_state=%d, pre_p2p_state=%d\n", __func__, rtw_p2p_role(pwdinfo), rtw_p2p_state(pwdinfo), rtw_p2p_pre_state(pwdinfo));
		}
	}
#endif /* CONFIG_P2P */

	if (check_fwstate(pmlmepriv, WIFI_MONITOR_STATE) != _TRUE) {
		WLAN_BSSID_EX  *pnetwork = &(padapter->mlmeextpriv.mlmext_info.network);
		struct wlan_network *scanned = pmlmepriv->cur_network_scanned;

		/* RTW_INFO(FUNC_ADPT_FMT" BSS not found\n", FUNC_ADPT_ARG(padapter)); */

		if (scanned == NULL) {
			rtw_warn_on(1);
			goto check_bss;
		}

		if (_rtw_memcmp(scanned->network.MacAddress, pnetwork->MacAddress, sizeof(NDIS_802_11_MAC_ADDRESS)) == _TRUE
			&& _rtw_memcmp(&(scanned->network.Ssid), &(pnetwork->Ssid), sizeof(NDIS_802_11_SSID)) == _TRUE
		) {
			if (!rtw_cfg80211_inform_bss(padapter, scanned))
				RTW_INFO(FUNC_ADPT_FMT" inform fail !!\n", FUNC_ADPT_ARG(padapter));
			else {
				/* RTW_INFO(FUNC_ADPT_FMT" inform success !!\n", FUNC_ADPT_ARG(padapter)); */
			}
		} else {
			RTW_INFO("scanned: %s("MAC_FMT"), cur: %s("MAC_FMT")\n",
				scanned->network.Ssid.Ssid, MAC_ARG(scanned->network.MacAddress),
				pnetwork->Ssid.Ssid, MAC_ARG(pnetwork->MacAddress)
			);
			rtw_warn_on(1);
		}
	}

check_bss:
	if (!rtw_cfg80211_check_bss(padapter))
		RTW_PRINT(FUNC_ADPT_FMT" BSS not found !!\n", FUNC_ADPT_ARG(padapter));

	if (rtw_to_roam(padapter) > 0) {
		#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39) || defined(COMPAT_KERNEL_RELEASE)
		struct wiphy *wiphy = pwdev->wiphy;
		struct ieee80211_channel *notify_channel;
		u32 freq;
		u16 channel = cur_network->network.Configuration.DSConfig;
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0))
		struct cfg80211_roam_info roam_info = {};
		#endif
		
		freq = rtw_ch2freq(channel);
		notify_channel = ieee80211_get_channel(wiphy, freq);
		#endif

		RTW_INFO(FUNC_ADPT_FMT" call cfg80211_roamed\n", FUNC_ADPT_ARG(padapter));
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0))
		roam_info.channel = notify_channel;
		roam_info.bssid = cur_network->network.MacAddress;
		roam_info.req_ie =
			pmlmepriv->assoc_req+sizeof(struct rtw_ieee80211_hdr_3addr)+2;
		roam_info.req_ie_len =
			pmlmepriv->assoc_req_len-sizeof(struct rtw_ieee80211_hdr_3addr)-2;
		roam_info.resp_ie =
			pmlmepriv->assoc_rsp+sizeof(struct rtw_ieee80211_hdr_3addr)+6;
		roam_info.resp_ie_len =
			pmlmepriv->assoc_rsp_len-sizeof(struct rtw_ieee80211_hdr_3addr)-6;
		cfg80211_roamed(padapter->pnetdev, &roam_info, GFP_ATOMIC);
		#else
		cfg80211_roamed(padapter->pnetdev
			#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39) || defined(COMPAT_KERNEL_RELEASE)
			, notify_channel
			#endif
			, cur_network->network.MacAddress
			, pmlmepriv->assoc_req + sizeof(struct rtw_ieee80211_hdr_3addr) + 2
			, pmlmepriv->assoc_req_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 2
			, pmlmepriv->assoc_rsp + sizeof(struct rtw_ieee80211_hdr_3addr) + 6
			, pmlmepriv->assoc_rsp_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 6
			, GFP_ATOMIC);
			#endif
	} else {
		#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) || defined(COMPAT_KERNEL_RELEASE)
		RTW_INFO("pwdev->sme_state(b)=%d\n", pwdev->sme_state);
		#endif
		cfg80211_connect_result(padapter->pnetdev, cur_network->network.MacAddress
			, pmlmepriv->assoc_req + sizeof(struct rtw_ieee80211_hdr_3addr) + 2
			, pmlmepriv->assoc_req_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 2
			, pmlmepriv->assoc_rsp + sizeof(struct rtw_ieee80211_hdr_3addr) + 6
			, pmlmepriv->assoc_rsp_len - sizeof(struct rtw_ieee80211_hdr_3addr) - 6
			, WLAN_STATUS_SUCCESS, GFP_ATOMIC);
		#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) || defined(COMPAT_KERNEL_RELEASE)
		RTW_INFO("pwdev->sme_state(a)=%d\n", pwdev->sme_state);
		#endif
	}
}

void rtw_cfg80211_indicate_disconnect(_adapter *padapter, u16 reason, u8 locally_generated)
{
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct wireless_dev *pwdev = padapter->rtw_wdev;
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &(padapter->wdinfo);
#endif

	RTW_INFO(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG(padapter));

	/*always replace privated definitions with wifi reserved value 0*/
	if ((reason == WLAN_REASON_ACTIVE_ROAM) || (reason == WLAN_REASON_JOIN_WRONG_CHANNEL) || (reason == WLAN_REASON_EXPIRATION_CHK))
		reason = 0;

	if (pwdev->iftype != NL80211_IFTYPE_STATION
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
		&& pwdev->iftype != NL80211_IFTYPE_P2P_CLIENT
		#endif
	)
		return;

	if (check_fwstate(pmlmepriv, WIFI_AP_STATE) == _TRUE)
		return;

#ifdef CONFIG_P2P
	if (pwdinfo->driver_interface == DRIVER_CFG80211) {
		if (!rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE)) {
			rtw_p2p_set_state(pwdinfo, rtw_p2p_pre_state(pwdinfo));

			#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
			if (pwdev->iftype != NL80211_IFTYPE_P2P_CLIENT)
			#endif
				rtw_p2p_set_role(pwdinfo, P2P_ROLE_DEVICE);

			RTW_INFO("%s, role=%d, p2p_state=%d, pre_p2p_state=%d\n", __func__, rtw_p2p_role(pwdinfo), rtw_p2p_state(pwdinfo), rtw_p2p_pre_state(pwdinfo));
		}
	}
#endif /* CONFIG_P2P */

	#ifdef SUPPLICANT_RTK_VERSION_LOWER_THAN_JB42
	if (!padapter->mlmepriv.not_indic_disco || padapter->ndev_unregistering) {
	#else
	{
	#endif
		#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) || defined(COMPAT_KERNEL_RELEASE)
		RTW_INFO("pwdev->sme_state(b)=%d\n", pwdev->sme_state);

		if (pwdev->sme_state == CFG80211_SME_CONNECTING)
			cfg80211_connect_result(padapter->pnetdev, NULL, NULL, 0, NULL, 0,
				WLAN_STATUS_UNSPECIFIED_FAILURE, GFP_ATOMIC/*GFP_KERNEL*/);
		else if (pwdev->sme_state == CFG80211_SME_CONNECTED) {
			#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0))
			cfg80211_disconnected(padapter->pnetdev, reason, NULL, 0, locally_generated, GFP_ATOMIC);
			#else
			cfg80211_disconnected(padapter->pnetdev, 0, NULL, 0, GFP_ATOMIC);
			#endif
		}
		#if 0
		else
			RTW_INFO("pwdev->sme_state=%d\n", pwdev->sme_state);
		#endif

		RTW_INFO("pwdev->sme_state(a)=%d\n", pwdev->sme_state);
		#else

		if (check_fwstate(&padapter->mlmepriv, _FW_LINKED)) {
			#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0))
			RTW_INFO(FUNC_ADPT_FMT" call cfg80211_disconnected\n", FUNC_ADPT_ARG(padapter));
			cfg80211_disconnected(padapter->pnetdev, reason, NULL, 0, locally_generated, GFP_ATOMIC);
			#else
			RTW_INFO(FUNC_ADPT_FMT" call cfg80211_disconnected\n", FUNC_ADPT_ARG(padapter));
			cfg80211_disconnected(padapter->pnetdev, 0, NULL, 0, GFP_ATOMIC);
			#endif
		} else {
			RTW_INFO(FUNC_ADPT_FMT" call cfg80211_connect_result\n", FUNC_ADPT_ARG(padapter));
			cfg80211_connect_result(padapter->pnetdev, NULL, NULL, 0, NULL, 0,
				WLAN_STATUS_UNSPECIFIED_FAILURE, GFP_ATOMIC);
		}
		#endif
	}
}


#ifdef CONFIG_AP_MODE
static int rtw_cfg80211_ap_set_encryption(struct net_device *dev, struct ieee_param *param, u32 param_len)
{
	int ret = 0;
	u32 wep_key_idx, wep_key_len, wep_total_len;
	struct sta_info *psta = NULL, *pbcmc_sta = NULL;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(dev);
	struct mlme_priv	*pmlmepriv = &padapter->mlmepriv;
	struct security_priv *psecuritypriv = &(padapter->securitypriv);
	struct sta_priv *pstapriv = &padapter->stapriv;

	RTW_INFO("%s\n", __FUNCTION__);

	param->u.crypt.err = 0;
	param->u.crypt.alg[IEEE_CRYPT_ALG_NAME_LEN - 1] = '\0';

	/* sizeof(struct ieee_param) = 64 bytes; */
	/* if (param_len !=  (u32) ((u8 *) param->u.crypt.key - (u8 *) param) + param->u.crypt.key_len) */
	if (param_len !=  sizeof(struct ieee_param) + param->u.crypt.key_len) {
		ret =  -EINVAL;
		goto exit;
	}

	if (param->sta_addr[0] == 0xff && param->sta_addr[1] == 0xff &&
	    param->sta_addr[2] == 0xff && param->sta_addr[3] == 0xff &&
	    param->sta_addr[4] == 0xff && param->sta_addr[5] == 0xff) {
		if (param->u.crypt.idx >= WEP_KEYS
#ifdef CONFIG_IEEE80211W
			&& param->u.crypt.idx > BIP_MAX_KEYID
#endif /* CONFIG_IEEE80211W */
		) {
			ret = -EINVAL;
			goto exit;
		}
	} else {
		psta = rtw_get_stainfo(pstapriv, param->sta_addr);
		if (!psta) {
			/* ret = -EINVAL; */
			RTW_INFO("rtw_set_encryption(), sta has already been removed or never been added\n");
			goto exit;
		}
	}

	if (strcmp(param->u.crypt.alg, "none") == 0 && (psta == NULL)) {
		/* todo:clear default encryption keys */

		RTW_INFO("clear default encryption keys, keyid=%d\n", param->u.crypt.idx);

		goto exit;
	}


	if (strcmp(param->u.crypt.alg, "WEP") == 0 && (psta == NULL)) {
		RTW_INFO("r871x_set_encryption, crypt.alg = WEP\n");

		wep_key_idx = param->u.crypt.idx;
		wep_key_len = param->u.crypt.key_len;

		RTW_INFO("r871x_set_encryption, wep_key_idx=%d, len=%d\n", wep_key_idx, wep_key_len);

		if ((wep_key_idx >= WEP_KEYS) || (wep_key_len <= 0)) {
			ret = -EINVAL;
			goto exit;
		}

		if (wep_key_len > 0)
			wep_key_len = wep_key_len <= 5 ? 5 : 13;

		if (psecuritypriv->bWepDefaultKeyIdxSet == 0) {
			/* wep default key has not been set, so use this key index as default key. */

			psecuritypriv->dot11AuthAlgrthm = dot11AuthAlgrthm_Auto;
			psecuritypriv->ndisencryptstatus = Ndis802_11Encryption1Enabled;
			psecuritypriv->dot11PrivacyAlgrthm = _WEP40_;
			psecuritypriv->dot118021XGrpPrivacy = _WEP40_;

			if (wep_key_len == 13) {
				psecuritypriv->dot11PrivacyAlgrthm = _WEP104_;
				psecuritypriv->dot118021XGrpPrivacy = _WEP104_;
			}

			psecuritypriv->dot11PrivacyKeyIndex = wep_key_idx;
		}

		_rtw_memcpy(&(psecuritypriv->dot11DefKey[wep_key_idx].skey[0]), param->u.crypt.key, wep_key_len);

		psecuritypriv->dot11DefKeylen[wep_key_idx] = wep_key_len;

		rtw_ap_set_wep_key(padapter, param->u.crypt.key, wep_key_len, wep_key_idx, 1);

		goto exit;

	}


	if (!psta && check_fwstate(pmlmepriv, WIFI_AP_STATE)) { /* group key */
		if (param->u.crypt.set_tx == 0) { /* group key */
			if (strcmp(param->u.crypt.alg, "WEP") == 0) {
				RTW_INFO("%s, set group_key, WEP\n", __FUNCTION__);

				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

				psecuritypriv->dot118021XGrpPrivacy = _WEP40_;
				if (param->u.crypt.key_len == 13)
					psecuritypriv->dot118021XGrpPrivacy = _WEP104_;

			} else if (strcmp(param->u.crypt.alg, "TKIP") == 0) {
				RTW_INFO("%s, set group_key, TKIP\n", __FUNCTION__);

				psecuritypriv->dot118021XGrpPrivacy = _TKIP_;

				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

				/* DEBUG_ERR("set key length :param->u.crypt.key_len=%d\n", param->u.crypt.key_len); */
				/* set mic key */
				_rtw_memcpy(psecuritypriv->dot118021XGrptxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[16]), 8);
				_rtw_memcpy(psecuritypriv->dot118021XGrprxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[24]), 8);

				psecuritypriv->busetkipkey = _TRUE;

			} else if (strcmp(param->u.crypt.alg, "CCMP") == 0) {
				RTW_INFO("%s, set group_key, CCMP\n", __FUNCTION__);

				psecuritypriv->dot118021XGrpPrivacy = _AES_;

				_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
			}
#ifdef CONFIG_IEEE80211W
			else if (strcmp(param->u.crypt.alg, "BIP") == 0) {
				int no;

				RTW_INFO("BIP key_len=%d , index=%d\n", param->u.crypt.key_len, param->u.crypt.idx);
				/* save the IGTK key, length 16 bytes */
				_rtw_memcpy(padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey, param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				/* RTW_INFO("IGTK key below:\n");
				for(no=0;no<16;no++)
					printk(" %02x ", padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey[no]);
				RTW_INFO("\n"); */
				padapter->securitypriv.dot11wBIPKeyid = param->u.crypt.idx;
				padapter->securitypriv.binstallBIPkey = _TRUE;
				RTW_INFO(" ~~~~set sta key:IGKT\n");
				goto exit;
			}
#endif /* CONFIG_IEEE80211W */
			else {
				RTW_INFO("%s, set group_key, none\n", __FUNCTION__);

				psecuritypriv->dot118021XGrpPrivacy = _NO_PRIVACY_;
			}

			psecuritypriv->dot118021XGrpKeyid = param->u.crypt.idx;

			psecuritypriv->binstallGrpkey = _TRUE;

			psecuritypriv->dot11PrivacyAlgrthm = psecuritypriv->dot118021XGrpPrivacy;/* !!! */

			rtw_ap_set_group_key(padapter, param->u.crypt.key, psecuritypriv->dot118021XGrpPrivacy, param->u.crypt.idx);

			pbcmc_sta = rtw_get_bcmc_stainfo(padapter);
			if (pbcmc_sta) {
				pbcmc_sta->ieee8021x_blocked = _FALSE;
				pbcmc_sta->dot118021XPrivacy = psecuritypriv->dot118021XGrpPrivacy; /* rx will use bmc_sta's dot118021XPrivacy			 */
			}

		}

		goto exit;

	}

	if (psecuritypriv->dot11AuthAlgrthm == dot11AuthAlgrthm_8021X && psta) { /* psk/802_1x */
		if (check_fwstate(pmlmepriv, WIFI_AP_STATE)) {
			if (param->u.crypt.set_tx == 1) { /* pairwise key */
				_rtw_memcpy(psta->dot118021x_UncstKey.skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

				if (strcmp(param->u.crypt.alg, "WEP") == 0) {
					RTW_INFO("%s, set pairwise key, WEP\n", __FUNCTION__);

					psta->dot118021XPrivacy = _WEP40_;
					if (param->u.crypt.key_len == 13)
						psta->dot118021XPrivacy = _WEP104_;
				} else if (strcmp(param->u.crypt.alg, "TKIP") == 0) {
					RTW_INFO("%s, set pairwise key, TKIP\n", __FUNCTION__);

					psta->dot118021XPrivacy = _TKIP_;

					/* DEBUG_ERR("set key length :param->u.crypt.key_len=%d\n", param->u.crypt.key_len); */
					/* set mic key */
					_rtw_memcpy(psta->dot11tkiptxmickey.skey, &(param->u.crypt.key[16]), 8);
					_rtw_memcpy(psta->dot11tkiprxmickey.skey, &(param->u.crypt.key[24]), 8);

					psecuritypriv->busetkipkey = _TRUE;

				} else if (strcmp(param->u.crypt.alg, "CCMP") == 0) {

					RTW_INFO("%s, set pairwise key, CCMP\n", __FUNCTION__);

					psta->dot118021XPrivacy = _AES_;
				} else {
					RTW_INFO("%s, set pairwise key, none\n", __FUNCTION__);

					psta->dot118021XPrivacy = _NO_PRIVACY_;
				}

				rtw_ap_set_pairwise_key(padapter, psta);

				psta->ieee8021x_blocked = _FALSE;

				psta->bpairwise_key_installed = _TRUE;

			} else { /* group key??? */
				if (strcmp(param->u.crypt.alg, "WEP") == 0) {
					_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

					psecuritypriv->dot118021XGrpPrivacy = _WEP40_;
					if (param->u.crypt.key_len == 13)
						psecuritypriv->dot118021XGrpPrivacy = _WEP104_;
				} else if (strcmp(param->u.crypt.alg, "TKIP") == 0) {
					psecuritypriv->dot118021XGrpPrivacy = _TKIP_;

					_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

					/* DEBUG_ERR("set key length :param->u.crypt.key_len=%d\n", param->u.crypt.key_len); */
					/* set mic key */
					_rtw_memcpy(psecuritypriv->dot118021XGrptxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[16]), 8);
					_rtw_memcpy(psecuritypriv->dot118021XGrprxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[24]), 8);

					psecuritypriv->busetkipkey = _TRUE;

				} else if (strcmp(param->u.crypt.alg, "CCMP") == 0) {
					psecuritypriv->dot118021XGrpPrivacy = _AES_;

					_rtw_memcpy(psecuritypriv->dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
				} else
					psecuritypriv->dot118021XGrpPrivacy = _NO_PRIVACY_;

				psecuritypriv->dot118021XGrpKeyid = param->u.crypt.idx;

				psecuritypriv->binstallGrpkey = _TRUE;

				psecuritypriv->dot11PrivacyAlgrthm = psecuritypriv->dot118021XGrpPrivacy;/* !!! */

				rtw_ap_set_group_key(padapter, param->u.crypt.key, psecuritypriv->dot118021XGrpPrivacy, param->u.crypt.idx);

				pbcmc_sta = rtw_get_bcmc_stainfo(padapter);
				if (pbcmc_sta) {
					pbcmc_sta->ieee8021x_blocked = _FALSE;
					pbcmc_sta->dot118021XPrivacy = psecuritypriv->dot118021XGrpPrivacy; /* rx will use bmc_sta's dot118021XPrivacy			 */
				}

			}

		}

	}

exit:

	return ret;

}
#endif

static int rtw_cfg80211_set_encryption(struct net_device *dev, struct ieee_param *param, u32 param_len)
{
	int ret = 0;
	u32 wep_key_idx, wep_key_len, wep_total_len;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(dev);
	struct mlme_priv	*pmlmepriv = &padapter->mlmepriv;
	struct security_priv *psecuritypriv = &padapter->securitypriv;
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &padapter->wdinfo;
#endif /* CONFIG_P2P */


	RTW_INFO("%s\n", __func__);

	param->u.crypt.err = 0;
	param->u.crypt.alg[IEEE_CRYPT_ALG_NAME_LEN - 1] = '\0';

	if (param_len < (u32)((u8 *) param->u.crypt.key - (u8 *) param) + param->u.crypt.key_len) {
		ret =  -EINVAL;
		goto exit;
	}

	if (param->sta_addr[0] == 0xff && param->sta_addr[1] == 0xff &&
	    param->sta_addr[2] == 0xff && param->sta_addr[3] == 0xff &&
	    param->sta_addr[4] == 0xff && param->sta_addr[5] == 0xff) {
		if (param->u.crypt.idx >= WEP_KEYS
#ifdef CONFIG_IEEE80211W
			&& param->u.crypt.idx > BIP_MAX_KEYID
#endif /* CONFIG_IEEE80211W */
		) {
			ret = -EINVAL;
			goto exit;
		}
	} else {
#ifdef CONFIG_WAPI_SUPPORT
		if (strcmp(param->u.crypt.alg, "SMS4"))
#endif
		{
			ret = -EINVAL;
			goto exit;
		}
	}

	if (strcmp(param->u.crypt.alg, "WEP") == 0) {
		RTW_INFO("wpa_set_encryption, crypt.alg = WEP\n");

		wep_key_idx = param->u.crypt.idx;
		wep_key_len = param->u.crypt.key_len;

		if ((wep_key_idx > WEP_KEYS) || (wep_key_len <= 0)) {
			ret = -EINVAL;
			goto exit;
		}

		if (psecuritypriv->bWepDefaultKeyIdxSet == 0) {
			/* wep default key has not been set, so use this key index as default key. */

			wep_key_len = wep_key_len <= 5 ? 5 : 13;

			psecuritypriv->ndisencryptstatus = Ndis802_11Encryption1Enabled;
			psecuritypriv->dot11PrivacyAlgrthm = _WEP40_;
			psecuritypriv->dot118021XGrpPrivacy = _WEP40_;

			if (wep_key_len == 13) {
				psecuritypriv->dot11PrivacyAlgrthm = _WEP104_;
				psecuritypriv->dot118021XGrpPrivacy = _WEP104_;
			}

			psecuritypriv->dot11PrivacyKeyIndex = wep_key_idx;
		}

		_rtw_memcpy(&(psecuritypriv->dot11DefKey[wep_key_idx].skey[0]), param->u.crypt.key, wep_key_len);

		psecuritypriv->dot11DefKeylen[wep_key_idx] = wep_key_len;

		rtw_set_key(padapter, psecuritypriv, wep_key_idx, 0, _TRUE);

		goto exit;
	}

	if (padapter->securitypriv.dot11AuthAlgrthm == dot11AuthAlgrthm_8021X) { /* 802_1x */
		struct sta_info *psta, *pbcmc_sta;
		struct sta_priv *pstapriv = &padapter->stapriv;

		/* RTW_INFO("%s, : dot11AuthAlgrthm == dot11AuthAlgrthm_8021X\n", __func__); */

		if (check_fwstate(pmlmepriv, WIFI_STATION_STATE | WIFI_MP_STATE) == _TRUE) { /* sta mode */
			psta = rtw_get_stainfo(pstapriv, get_bssid(pmlmepriv));
			if (psta == NULL) {
				/* DEBUG_ERR( ("Set wpa_set_encryption: Obtain Sta_info fail\n")); */
				RTW_INFO("%s, : Obtain Sta_info fail\n", __func__);
			} else {
				/* Jeff: don't disable ieee8021x_blocked while clearing key */
				if (strcmp(param->u.crypt.alg, "none") != 0)
					psta->ieee8021x_blocked = _FALSE;


				if ((padapter->securitypriv.ndisencryptstatus == Ndis802_11Encryption2Enabled) ||
				    (padapter->securitypriv.ndisencryptstatus ==  Ndis802_11Encryption3Enabled))
					psta->dot118021XPrivacy = padapter->securitypriv.dot11PrivacyAlgrthm;

				if (param->u.crypt.set_tx == 1) { /* pairwise key */

					RTW_INFO("%s, : param->u.crypt.set_tx ==1\n", __func__);

					_rtw_memcpy(psta->dot118021x_UncstKey.skey,  param->u.crypt.key, (param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));

					if (strcmp(param->u.crypt.alg, "TKIP") == 0) { /* set mic key */
						/* DEBUG_ERR(("\nset key length :param->u.crypt.key_len=%d\n", param->u.crypt.key_len)); */
						_rtw_memcpy(psta->dot11tkiptxmickey.skey, &(param->u.crypt.key[16]), 8);
						_rtw_memcpy(psta->dot11tkiprxmickey.skey, &(param->u.crypt.key[24]), 8);

						padapter->securitypriv.busetkipkey = _FALSE;
						/* _set_timer(&padapter->securitypriv.tkip_timer, 50);						 */
					}
					psta->bpairwise_key_installed = _TRUE;
					/* DEBUG_ERR((" param->u.crypt.key_len=%d\n",param->u.crypt.key_len)); */
					RTW_INFO(" ~~~~set sta key:unicastkey\n");

					rtw_setstakey_cmd(padapter, psta, UNICAST_KEY, _TRUE);
				} else { /* group key */
					if (strcmp(param->u.crypt.alg, "TKIP") == 0 || strcmp(param->u.crypt.alg, "CCMP") == 0) {
						_rtw_memcpy(padapter->securitypriv.dot118021XGrpKey[param->u.crypt.idx].skey,  param->u.crypt.key,
							(param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
						_rtw_memcpy(padapter->securitypriv.dot118021XGrptxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[16]), 8);
						_rtw_memcpy(padapter->securitypriv.dot118021XGrprxmickey[param->u.crypt.idx].skey, &(param->u.crypt.key[24]), 8);
						padapter->securitypriv.binstallGrpkey = _TRUE;
						/* DEBUG_ERR((" param->u.crypt.key_len=%d\n", param->u.crypt.key_len)); */
						RTW_INFO(" ~~~~set sta key:groupkey\n");

						padapter->securitypriv.dot118021XGrpKeyid = param->u.crypt.idx;
						rtw_set_key(padapter, &padapter->securitypriv, param->u.crypt.idx, 1, _TRUE);
					}
#ifdef CONFIG_IEEE80211W
					else if (strcmp(param->u.crypt.alg, "BIP") == 0) {
						int no;
						/* RTW_INFO("BIP key_len=%d , index=%d @@@@@@@@@@@@@@@@@@\n", param->u.crypt.key_len, param->u.crypt.idx); */
						/* save the IGTK key, length 16 bytes */
						_rtw_memcpy(padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey,  param->u.crypt.key,
							(param->u.crypt.key_len > 16 ? 16 : param->u.crypt.key_len));
						/*RTW_INFO("IGTK key below:\n");
						for(no=0;no<16;no++)
							printk(" %02x ", padapter->securitypriv.dot11wBIPKey[param->u.crypt.idx].skey[no]);
						RTW_INFO("\n");*/
						padapter->securitypriv.dot11wBIPKeyid = param->u.crypt.idx;
						padapter->securitypriv.binstallBIPkey = _TRUE;
						RTW_INFO(" ~~~~set sta key:IGKT\n");
					}
#endif /* CONFIG_IEEE80211W */

#ifdef CONFIG_P2P
					if (pwdinfo->driver_interface == DRIVER_CFG80211) {
						if (rtw_p2p_chk_state(pwdinfo, P2P_STATE_PROVISIONING_ING))
							rtw_p2p_set_state(pwdinfo, P2P_STATE_PROVISIONING_DONE);
					}
#endif /* CONFIG_P2P */

				}
			}

			pbcmc_sta = rtw_get_bcmc_stainfo(padapter);
			if (pbcmc_sta == NULL) {
				/* DEBUG_ERR( ("Set OID_802_11_ADD_KEY: bcmc stainfo is null\n")); */
			} else {
				/* Jeff: don't disable ieee8021x_blocked while clearing key */
				if (strcmp(param->u.crypt.alg, "none") != 0)
					pbcmc_sta->ieee8021x_blocked = _FALSE;

				if ((padapter->securitypriv.ndisencryptstatus == Ndis802_11Encryption2Enabled) ||
				    (padapter->securitypriv.ndisencryptstatus ==  Ndis802_11Encryption3Enabled))
					pbcmc_sta->dot118021XPrivacy = padapter->securitypriv.dot11PrivacyAlgrthm;
			}
		} else if (check_fwstate(pmlmepriv, WIFI_ADHOC_STATE)) { /* adhoc mode */
		}
	}

#ifdef CONFIG_WAPI_SUPPORT
	if (strcmp(param->u.crypt.alg, "SMS4") == 0) {
		PRT_WAPI_T			pWapiInfo = &padapter->wapiInfo;
		PRT_WAPI_STA_INFO	pWapiSta;
		u8					WapiASUEPNInitialValueSrc[16] = {0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C} ;
		u8					WapiAEPNInitialValueSrc[16] = {0x37, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C} ;
		u8					WapiAEMultiCastPNInitialValueSrc[16] = {0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C, 0x36, 0x5C} ;

		if (param->u.crypt.set_tx == 1) {
			list_for_each_entry(pWapiSta, &pWapiInfo->wapiSTAUsedList, list) {
				if (_rtw_memcmp(pWapiSta->PeerMacAddr, param->sta_addr, 6)) {
					_rtw_memcpy(pWapiSta->lastTxUnicastPN, WapiASUEPNInitialValueSrc, 16);

					pWapiSta->wapiUsk.bSet = true;
					_rtw_memcpy(pWapiSta->wapiUsk.dataKey, param->u.crypt.key, 16);
					_rtw_memcpy(pWapiSta->wapiUsk.micKey, param->u.crypt.key + 16, 16);
					pWapiSta->wapiUsk.keyId = param->u.crypt.idx ;
					pWapiSta->wapiUsk.bTxEnable = true;

					_rtw_memcpy(pWapiSta->lastRxUnicastPNBEQueue, WapiAEPNInitialValueSrc, 16);
					_rtw_memcpy(pWapiSta->lastRxUnicastPNBKQueue, WapiAEPNInitialValueSrc, 16);
					_rtw_memcpy(pWapiSta->lastRxUnicastPNVIQueue, WapiAEPNInitialValueSrc, 16);
					_rtw_memcpy(pWapiSta->lastRxUnicastPNVOQueue, WapiAEPNInitialValueSrc, 16);
					_rtw_memcpy(pWapiSta->lastRxUnicastPN, WapiAEPNInitialValueSrc, 16);
					pWapiSta->wapiUskUpdate.bTxEnable = false;
					pWapiSta->wapiUskUpdate.bSet = false;

					if (psecuritypriv->sw_encrypt == false || psecuritypriv->sw_decrypt == false) {
						/* set unicast key for ASUE */
						rtw_wapi_set_key(padapter, &pWapiSta->wapiUsk, pWapiSta, false, false);
					}
				}
			}
		} else {
			list_for_each_entry(pWapiSta, &pWapiInfo->wapiSTAUsedList, list) {
				if (_rtw_memcmp(pWapiSta->PeerMacAddr, get_bssid(pmlmepriv), 6)) {
					pWapiSta->wapiMsk.bSet = true;
					_rtw_memcpy(pWapiSta->wapiMsk.dataKey, param->u.crypt.key, 16);
					_rtw_memcpy(pWapiSta->wapiMsk.micKey, param->u.crypt.key + 16, 16);
					pWapiSta->wapiMsk.keyId = param->u.crypt.idx ;
					pWapiSta->wapiMsk.bTxEnable = false;
					if (!pWapiSta->bSetkeyOk)
						pWapiSta->bSetkeyOk = true;
					pWapiSta->bAuthenticateInProgress = false;

					_rtw_memcpy(pWapiSta->lastRxMulticastPN, WapiAEMultiCastPNInitialValueSrc, 16);

					if (psecuritypriv->sw_decrypt == false) {
						/* set rx broadcast key for ASUE */
						rtw_wapi_set_key(padapter, &pWapiSta->wapiMsk, pWapiSta, true, false);
					}
				}

			}
		}
	}
#endif


exit:

	RTW_INFO("%s, ret=%d\n", __func__, ret);


	return ret;
}

static int cfg80211_rtw_add_key(struct wiphy *wiphy, struct net_device *ndev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
	u8 key_index, bool pairwise, const u8 *mac_addr,
#else	/* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
	u8 key_index, const u8 *mac_addr,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
	struct key_params *params)
{
	char *alg_name;
	u32 param_len;
	struct ieee_param *param = NULL;
	int ret = 0;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct wireless_dev *rtw_wdev = padapter->rtw_wdev;
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
#ifdef CONFIG_TDLS
	struct sta_info *ptdls_sta;
#endif /* CONFIG_TDLS */

	RTW_INFO(FUNC_NDEV_FMT" adding key for %pM\n", FUNC_NDEV_ARG(ndev), mac_addr);
	RTW_INFO("cipher=0x%x\n", params->cipher);
	RTW_INFO("key_len=0x%x\n", params->key_len);
	RTW_INFO("seq_len=0x%x\n", params->seq_len);
	RTW_INFO("key_index=%d\n", key_index);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
	RTW_INFO("pairwise=%d\n", pairwise);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */

	param_len = sizeof(struct ieee_param) + params->key_len;
	param = (struct ieee_param *)rtw_malloc(param_len);
	if (param == NULL)
		return -1;

	_rtw_memset(param, 0, param_len);

	param->cmd = IEEE_CMD_SET_ENCRYPTION;
	_rtw_memset(param->sta_addr, 0xff, ETH_ALEN);

	switch (params->cipher) {
	case IW_AUTH_CIPHER_NONE:
		/* todo: remove key */
		/* remove = 1;	 */
		alg_name = "none";
		break;
	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
		alg_name = "WEP";
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		alg_name = "TKIP";
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		alg_name = "CCMP";
		break;
#ifdef CONFIG_IEEE80211W
	case WLAN_CIPHER_SUITE_AES_CMAC:
		alg_name = "BIP";
		break;
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_WAPI_SUPPORT
	case WLAN_CIPHER_SUITE_SMS4:
		alg_name = "SMS4";
		if (pairwise == NL80211_KEYTYPE_PAIRWISE) {
			if (key_index != 0 && key_index != 1) {
				ret = -ENOTSUPP;
				goto addkey_end;
			}
			_rtw_memcpy((void *)param->sta_addr, (void *)mac_addr, ETH_ALEN);
		} else
			RTW_INFO("mac_addr is null\n");
		RTW_INFO("rtw_wx_set_enc_ext: SMS4 case\n");
		break;
#endif

	default:
		ret = -ENOTSUPP;
		goto addkey_end;
	}

	strncpy((char *)param->u.crypt.alg, alg_name, IEEE_CRYPT_ALG_NAME_LEN);


	if (!mac_addr || is_broadcast_ether_addr(mac_addr)) {
		param->u.crypt.set_tx = 0; /* for wpa/wpa2 group key */
	} else {
		param->u.crypt.set_tx = 1; /* for wpa/wpa2 pairwise key */
	}


	/* param->u.crypt.idx = key_index - 1; */
	param->u.crypt.idx = key_index;

	if (params->seq_len && params->seq)
		_rtw_memcpy(param->u.crypt.seq, (u8 *)params->seq, params->seq_len);

	if (params->key_len && params->key) {
		param->u.crypt.key_len = params->key_len;
		_rtw_memcpy(param->u.crypt.key, (u8 *)params->key, params->key_len);
	}

	if (check_fwstate(pmlmepriv, WIFI_STATION_STATE) == _TRUE) {
#ifdef CONFIG_TDLS
		if (rtw_tdls_is_driver_setup(padapter) == _FALSE && mac_addr) {
			ptdls_sta = rtw_get_stainfo(&padapter->stapriv, (void *)mac_addr);
			if (ptdls_sta != NULL && ptdls_sta->tdls_sta_state) {
				_rtw_memcpy(ptdls_sta->tpk.tk, params->key, params->key_len);
				rtw_tdls_set_key(padapter, ptdls_sta);
				goto addkey_end;
			}
		}
#endif /* CONFIG_TDLS */

		ret =  rtw_cfg80211_set_encryption(ndev, param, param_len);
	} else if (check_fwstate(pmlmepriv, WIFI_AP_STATE) == _TRUE) {
#ifdef CONFIG_AP_MODE
		if (mac_addr)
			_rtw_memcpy(param->sta_addr, (void *)mac_addr, ETH_ALEN);

		ret = rtw_cfg80211_ap_set_encryption(ndev, param, param_len);
#endif
	} else if (check_fwstate(pmlmepriv, WIFI_ADHOC_STATE) == _TRUE
		|| check_fwstate(pmlmepriv, WIFI_ADHOC_MASTER_STATE) == _TRUE
	) {
		/* RTW_INFO("@@@@@@@@@@ fw_state=0x%x, iftype=%d\n", pmlmepriv->fw_state, rtw_wdev->iftype); */
		ret =  rtw_cfg80211_set_encryption(ndev, param, param_len);
	} else
		RTW_INFO("error! fw_state=0x%x, iftype=%d\n", pmlmepriv->fw_state, rtw_wdev->iftype);


addkey_end:
	if (param)
		rtw_mfree((u8 *)param, param_len);

	return ret;

}

static int cfg80211_rtw_get_key(struct wiphy *wiphy, struct net_device *ndev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
	u8 key_index, bool pairwise, const u8 *mac_addr,
#else	/* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
	u8 key_index, const u8 *mac_addr,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
	void *cookie,
	void (*callback)(void *cookie, struct key_params *))
{
#if 0
	struct iwm_priv *iwm = ndev_to_iwm(ndev);
	struct iwm_key *key = &iwm->keys[key_index];
	struct key_params params;

	IWM_DBG_WEXT(iwm, DBG, "Getting key %d\n", key_index);

	memset(&params, 0, sizeof(params));

	params.cipher = key->cipher;
	params.key_len = key->key_len;
	params.seq_len = key->seq_len;
	params.seq = key->seq;
	params.key = key->key;

	callback(cookie, &params);

	return key->key_len ? 0 : -ENOENT;
#endif
	RTW_INFO(FUNC_NDEV_FMT"\n", FUNC_NDEV_ARG(ndev));
	return 0;
}

static int cfg80211_rtw_del_key(struct wiphy *wiphy, struct net_device *ndev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE)
				u8 key_index, bool pairwise, const u8 *mac_addr)
#else	/* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
				u8 key_index, const u8 *mac_addr)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) */
{
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct security_priv *psecuritypriv = &padapter->securitypriv;

	RTW_INFO(FUNC_NDEV_FMT" key_index=%d\n", FUNC_NDEV_ARG(ndev), key_index);

	if (key_index == psecuritypriv->dot11PrivacyKeyIndex) {
		/* clear the flag of wep default key set. */
		psecuritypriv->bWepDefaultKeyIdxSet = 0;
	}

	return 0;
}

static int cfg80211_rtw_set_default_key(struct wiphy *wiphy,
	struct net_device *ndev, u8 key_index
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)) || defined(COMPAT_KERNEL_RELEASE)
	, bool unicast, bool multicast
	#endif
)
{
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct security_priv *psecuritypriv = &padapter->securitypriv;

#define SET_DEF_KEY_PARAM_FMT " key_index=%d"
#define SET_DEF_KEY_PARAM_ARG , key_index
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)) || defined(COMPAT_KERNEL_RELEASE)
	#define SET_DEF_KEY_PARAM_FMT_2_6_38 ", unicast=%d, multicast=%d"
	#define SET_DEF_KEY_PARAM_ARG_2_6_38 , unicast, multicast
#else
	#define SET_DEF_KEY_PARAM_FMT_2_6_38 ""
	#define SET_DEF_KEY_PARAM_ARG_2_6_38
#endif

	RTW_INFO(FUNC_NDEV_FMT
		SET_DEF_KEY_PARAM_FMT
		SET_DEF_KEY_PARAM_FMT_2_6_38
		"\n", FUNC_NDEV_ARG(ndev)
		SET_DEF_KEY_PARAM_ARG
		SET_DEF_KEY_PARAM_ARG_2_6_38
	);

	if ((key_index < WEP_KEYS) && ((psecuritypriv->dot11PrivacyAlgrthm == _WEP40_) || (psecuritypriv->dot11PrivacyAlgrthm == _WEP104_))) { /* set wep default key */
		psecuritypriv->ndisencryptstatus = Ndis802_11Encryption1Enabled;

		psecuritypriv->dot11PrivacyKeyIndex = key_index;

		psecuritypriv->dot11PrivacyAlgrthm = _WEP40_;
		psecuritypriv->dot118021XGrpPrivacy = _WEP40_;
		if (psecuritypriv->dot11DefKeylen[key_index] == 13) {
			psecuritypriv->dot11PrivacyAlgrthm = _WEP104_;
			psecuritypriv->dot118021XGrpPrivacy = _WEP104_;
		}

		psecuritypriv->bWepDefaultKeyIdxSet = 1; /* set the flag to represent that wep default key has been set */
	}

	return 0;

}
#if defined(CONFIG_GTK_OL) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
static int cfg80211_rtw_set_rekey_data(struct wiphy *wiphy,
	struct net_device *ndev,
	struct cfg80211_gtk_rekey_data *data)
{
	/*int i;*/
	struct sta_info *psta;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct mlme_priv   *pmlmepriv = &padapter->mlmepriv;
	struct sta_priv *pstapriv = &padapter->stapriv;
	struct security_priv *psecuritypriv = &(padapter->securitypriv);

	psta = rtw_get_stainfo(pstapriv, get_bssid(pmlmepriv));
	if (psta == NULL) {
		RTW_INFO("%s, : Obtain Sta_info fail\n", __func__);
		return -1;
	}

	_rtw_memcpy(psta->kek, data->kek, NL80211_KEK_LEN);
	/*printk("\ncfg80211_rtw_set_rekey_data KEK:");
	for(i=0;i<NL80211_KEK_LEN; i++)
		printk(" %02x ", psta->kek[i]);*/
	_rtw_memcpy(psta->kck, data->kck, NL80211_KCK_LEN);
	/*printk("\ncfg80211_rtw_set_rekey_data KCK:");
	for(i=0;i<NL80211_KCK_LEN; i++)
		printk(" %02x ", psta->kck[i]);*/
	_rtw_memcpy(psta->replay_ctr, data->replay_ctr, NL80211_REPLAY_CTR_LEN);
	psecuritypriv->binstallKCK_KEK = _TRUE;
	/*printk("\nREPLAY_CTR: ");
	for(i=0;i<RTW_REPLAY_CTR_LEN; i++)
		printk(" %02x ", psta->replay_ctr[i]);*/

	return 0;
}
#endif /*CONFIG_GTK_OL*/
static int cfg80211_rtw_get_station(struct wiphy *wiphy,
	struct net_device *ndev,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0))
	u8 *mac,
#else
	const u8 *mac,
#endif
	struct station_info *sinfo)
{
	int ret = 0;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct sta_info *psta = NULL;
	struct sta_priv *pstapriv = &padapter->stapriv;

	sinfo->filled = 0;

	if (!mac) {
		RTW_INFO(FUNC_NDEV_FMT" mac==%p\n", FUNC_NDEV_ARG(ndev), mac);
		ret = -ENOENT;
		goto exit;
	}

	psta = rtw_get_stainfo(pstapriv, (u8 *)mac);
	if (psta == NULL) {
		RTW_INFO("%s, sta_info is null\n", __func__);
		ret = -ENOENT;
		goto exit;
	}

#ifdef CONFIG_DEBUG_CFG80211
	RTW_INFO(FUNC_NDEV_FMT" mac="MAC_FMT"\n", FUNC_NDEV_ARG(ndev), MAC_ARG(mac));
#endif

	/* for infra./P2PClient mode */
	if (check_fwstate(pmlmepriv, WIFI_STATION_STATE)
		&& check_fwstate(pmlmepriv, _FW_LINKED)
	) {
		struct wlan_network  *cur_network = &(pmlmepriv->cur_network);

		if (_rtw_memcmp((u8 *)mac, cur_network->network.MacAddress, ETH_ALEN) == _FALSE) {
			RTW_INFO("%s, mismatch bssid="MAC_FMT"\n", __func__, MAC_ARG(cur_network->network.MacAddress));
			ret = -ENOENT;
			goto exit;
		}

		sinfo->filled |= STATION_INFO_SIGNAL;
		sinfo->signal = translate_percentage_to_dbm(padapter->recvpriv.signal_strength);

		sinfo->filled |= STATION_INFO_TX_BITRATE;
		sinfo->txrate.legacy = rtw_get_cur_max_rate(padapter);

		sinfo->filled |= STATION_INFO_RX_PACKETS;
		sinfo->rx_packets = sta_rx_data_pkts(psta);

		sinfo->filled |= STATION_INFO_TX_PACKETS;
		sinfo->tx_packets = psta->sta_stats.tx_pkts;

	}

	/* for Ad-Hoc/AP mode */
	if ((check_fwstate(pmlmepriv, WIFI_ADHOC_STATE)
		|| check_fwstate(pmlmepriv, WIFI_ADHOC_MASTER_STATE)
		|| check_fwstate(pmlmepriv, WIFI_AP_STATE))
		&& check_fwstate(pmlmepriv, _FW_LINKED)
	) {
		/* TODO: should acquire station info... */
	}

exit:
	return ret;
}

extern int netdev_open(struct net_device *pnetdev);

#if 0
enum nl80211_iftype {
	NL80211_IFTYPE_UNSPECIFIED,
	NL80211_IFTYPE_ADHOC, /* 1 */
	NL80211_IFTYPE_STATION, /* 2 */
	NL80211_IFTYPE_AP, /* 3 */
	NL80211_IFTYPE_AP_VLAN,
	NL80211_IFTYPE_WDS,
	NL80211_IFTYPE_MONITOR, /* 6 */
	NL80211_IFTYPE_MESH_POINT,
	NL80211_IFTYPE_P2P_CLIENT, /* 8 */
	NL80211_IFTYPE_P2P_GO, /* 9 */
	/* keep last */
	NUM_NL80211_IFTYPES,
	NL80211_IFTYPE_MAX = NUM_NL80211_IFTYPES - 1
};
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
static int cfg80211_rtw_change_iface(struct wiphy *wiphy,
				     struct net_device *ndev,
				     enum nl80211_iftype type,
				     struct vif_params *params)
#else
static int cfg80211_rtw_change_iface(struct wiphy *wiphy,
				     struct net_device *ndev,
				     enum nl80211_iftype type, u32 *flags,
				     struct vif_params *params)
#endif
{
	enum nl80211_iftype old_type;
	NDIS_802_11_NETWORK_INFRASTRUCTURE networkType;
	_adapter *padapter = (_adapter *)rtw_netdev_priv(ndev);
	struct wireless_dev *rtw_wdev = padapter->rtw_wdev;
	struct mlme_ext_priv	*pmlmeext = &(padapter->mlmeextpriv);
#ifdef CONFIG_P2P
	struct wifidirect_info *pwdinfo = &(padapter->wdinfo);
#endif
	int ret = 0;
	u8 change = _FALSE;

	RTW_INFO(FUNC_NDEV_FMT" type=%d, hw_port:%d\n", FUNC_NDEV_ARG(ndev), type, padapter->hw_port);

	if (adapter_to_dvobj(padapter)->processing_dev_remove == _TRUE) {
		ret = -EPERM;
		goto exit;
	}


	RTW_INFO(FUNC_NDEV_FMT" call netdev_open\n", FUNC_NDEV_ARG(ndev));
	if (netdev_open(ndev) != 0) {
		RTW_INFO(FUNC_NDEV_FMT" call netdev_open fail\n", FUNC_NDEV_ARG(ndev));
		ret = -EPERM;
		goto exit;
	}


	if (_FAIL == rtw_pwr_wakeup(padapter)) {
		RTW_INFO(FUNC_NDEV_FMT" call rtw_pwr_wakeup fail\n", FUNC_NDEV_ARG(ndev));
		ret = -EPERM;
		goto exit;
	}

	old_type = rtw_wdev->iftype;
	RTW_INFO(FUNC_NDEV_FMT" old_iftype=%d, new_iftype=%d\n",
		FUNC_NDEV_ARG(ndev), old_type, type);

	if (old_type != type) {
		change = _TRUE;
		pmlmeext->action_public_rxseq = 0xffff;
		pmlmeext->action_public_dialog_token = 0xff;
	}

	/* initial default type */
	ndev->type = ARPHRD_ETHER;

	if (type == NL80211_IFTYPE_MONITOR) {
		rtw_ps_deny(padapter, PS_DENY_MONITOR_MODE);
		LeaveAllPowerSaveMode(padapter);
	} else {
		rtw_ps_deny_cancel(padapter, PS_DENY_MONITOR_MODE);
	}

	switch (type) {
	case NL80211_IFTYPE_ADHOC:
		networkType = Ndis802_11IBSS;
		break;
#if defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
	case NL80211_IFTYPE_P2P_CLIENT:
#endif
	case NL80211_IFTYPE_STATION:
		networkType = Ndis802_11Infrastructure;
		#ifdef CONFIG_P2P
		if (pwdinfo->driver_interface == DRIVER_CFG80211) {
			if (change && rtw_p2p_chk_role(pwdinfo, P2P_ROLE_GO)) {
				/* it means remove GO and change mode from AP(GO) to station(P2P DEVICE) */
				rtw_p2p_set_role(pwdinfo, P2P_ROLE_DEVICE);
				rtw_p2p_set_state(pwdinfo, rtw_p2p_pre_state(pwdinfo));

				RTW_INFO("%s, role=%d, p2p_state=%d, pre_p2p_state=%d\n", __func__, rtw_p2p_role(pwdinfo), rtw_p2p_state(pwdinfo), rtw_p2p_pre_state(pwdinfo));
			}
			#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
			if (type == NL80211_IFTYPE_P2P_CLIENT)
				rtw_p2p_set_role(pwdinfo, P2P_ROLE_CLIENT);
			else {
				/* NL80211_IFTYPE_STATION */
				if (rtw_p2p_role(pwdinfo) == P2P_ROLE_CLIENT)
					rtw_p2p_set_role(pwdinfo, P2P_ROLE_DEVICE);
			}
			#endif
		}
		#endif /* CONFIG_P2P */
		break;
#if defined(CONFIG_P2P) && ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)) || defined(COMPAT_KERNEL_RELEASE))
	case NL80211_IFTYPE_P2P_GO:
#endif
	case NL80211_IFTYPE_AP:
		networkType = Ndis802_11APMode;
		#ifdef CONFIG_P2P
		if (pwdinfo->driver_interface == DRIVER_CFG80211) {
			if (change && !rtw_p2p_chk_state(pwdinfo, P2P_STATE_NONE)) {
				/* it means P2P Group created, we will be GO and change mode from  P2P DEVICE to AP(GO) */
				rtw_p2p_set_role(pwdinfo, P2P_ROLE_GO);
			}
		}
		#endif /* CONFIG_P2P */
		break;
	case NL80211_IFTYPE_MONITOR:
		networkType = Ndis802_11Monitor;
#if 0
		ndev->type = ARPHRD_IEEE80211; /* IEEE 802.11 : 801 */
#endif
		ndev->type = ARPHRD_IEEE80211_RADIOTAP; /* IEEE 802.11 + radiotap header : 803 */
		break;
	default:
		ret = -EOPNOTSUPP;
		goto exit;
	}

	rtw_wdev->iftype = type;

	if (rtw_set_802_11_infrastructure_mode(padapter, networkType) == _FALSE) {
		rtw_wdev->iftype = old_type;
		ret = -EPERM;
		goto exit;
	}

	rtw_setopmode_cmd(padapter, networkType, _TRUE);

exit:

	RTW_INFO(FUNC_NDEV_FMT" ret:%d\n", FUNC_NDEV_ARG(ndev), ret);
	return ret;
}

void rtw_cfg80211_indicate_scan_done(_adapter *adapter, bool aborted)
{
	struct rtw_wdev_priv *pwdev_priv = adapter_wdev_data(adapter);
	_irqL	irqL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
	struct cfg80211_scan_info info;
#endif // (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))

	_enter_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
	if (pwdev_priv->scan_request != NULL) {
		#ifdef CONFIG_DEBUG_CFG80211
		RTW_INFO("%s with scan req\n", __FUNCTION__);
		#endif

		/* avoid WARN_ON(request != wiphy_to_dev(request->wiphy)->scan_req); */
		if (pwdev_priv->scan_request->wiphy != pwdev_priv->rtw_wdev->wiphy)
			RTW_INFO("error wiphy compare\n");
		else
		{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
			memset(&info, 0, sizeof(info));
			info.aborted = aborted;
			cfg80211_scan_done(pwdev_priv->scan_request, &info);
#else // (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
			cfg80211_scan_done(pwdev_priv->scan_request, aborted);
#endif // (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0))
		}

		pwdev_priv->scan_request = NULL;
	} else {
		#ifdef CONFIG_DEBUG_CFG80211
		RTW_INFO("%s without scan req\n", __FUNCTION__);
		#endif
	}
	_exit_critical_bh(&pwdev_priv->scan_req_lock, &irqL);
}

u32 rtw_cfg80211_wait_scan_req_empty(_adapter *adapter, u32 timeout_ms)
{
	struct rtw_wdev_priv *wdev_priv = adapter_wdev_data(adapter);
	u8 empty = _FALSE;
	u32 start;
	u32 pass_ms;

	start = rtw_get_current_time();

	while
