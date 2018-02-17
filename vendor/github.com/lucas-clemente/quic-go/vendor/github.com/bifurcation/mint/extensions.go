package mint

import (
	"bytes"
	"fmt"
	"github.com/bifurcation/mint/syntax"
)

type ExtensionBody interface {
	Type() ExtensionType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ExtensionType extension_type;
//     opaque extension_data<0..2^16-1>;
// } Extension;
type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte `tls:"head=2"`
}

func (ext Extension) Marshal() ([]byte, error) {
	return syntax.Marshal(ext)
}

func (ext *Extension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ext)
}

type ExtensionList []Extension

type extensionListInner struct {
	List []Extension `tls:"head=2"`
}

func (el ExtensionList) Marshal() ([]byte, error) {
	return syntax.Marshal(extensionListInner{el})
}

func (el *ExtensionList) Unmarshal(data []byte) (int, error) {
	var list extensionListInner
	read, err := syntax.Unmarshal(data, &list)
	if err != nil {
		return 0, err
	}

	*el = list.List
	return read, nil
}

func (el *ExtensionList) Add(src ExtensionBody) error {
	data, err := src.Marshal()
	if err != nil {
		return err
	}

	if el == nil {
		el = new(ExtensionList)
	}

	// If one already exists with this type, replace it
	for i := range *el {
		if (*el)[i].ExtensionType == src.Type() {
			(*el)[i].ExtensionData = data
			return nil
		}
	}

	// Otherwise append
	*el = append(*el, Extension{
		ExtensionType: src.Type(),
		ExtensionData: data,
	})
	return nil
}

func (el ExtensionList) Parse(dsts []ExtensionBody) (map[ExtensionType]bool, error) {
	found := make(map[ExtensionType]bool)

	for _, dst := range dsts {
		for _, ext := range el {
			if ext.ExtensionType == dst.Type() {
				if found[dst.Type()] {
					return nil, fmt.Errorf("Duplicate extension of type [%v]", dst.Type())
				}

				err := safeUnmarshal(dst, ext.ExtensionData)
				if err != nil {
					return nil, err
				}

				found[dst.Type()] = true
			}
		}
	}

	return found, nil
}

func (el ExtensionList) Find(dst ExtensionBody) (bool, error) {
	for _, ext := range el {
		if ext.ExtensionType == dst.Type() {
			err := safeUnmarshal(dst, ext.ExtensionData)
			if err != nil {
				return true, err
			}
			return true, nil
		}
	}
	return false, nil
}

// struct {
//     NameType name_type;
//     select (name_type) {
//         case host_name: HostName;
//     } name;
// } ServerName;
//
// enum {
//     host_name(0), (255)
// } NameType;
//
// opaque HostName<1..2^16-1>;
//
// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
//
// But we only care about the case where there's a single DNS hostname.  We
// will never create anything else, and throw if we receive something else
//
//      2         1          2
// | listLen | NameType | nameLen | name |
type ServerNameExtension string

type serverNameInner struct {
	NameType uint8
	HostName []byte `tls:"head=2,min=1"`
}

type serverNameListInner struct {
	ServerNameList []serverNameInner `tls:"head=2,min=1"`
}

func (sni ServerNameExtension) Type() ExtensionType {
	return ExtensionTypeServerName
}

func (sni ServerNameExtension) Marshal() ([]byte, error) {
	list := serverNameListInner{
		ServerNameList: []serverNameInner{{
			NameType: 0x00, // host_name
			HostName: []byte(sni),
		}},
	}

	return syntax.Marshal(list)
}

func (sni *ServerNameExtension) Unmarshal(data []byte) (int, error) {
	var list serverNameListInner
	read, err := syntax.Unmarshal(data, &list)
	if err != nil {
		return 0, err
	}

	// Syntax requires at least one entry
	// Entries beyond the first are ignored
	if nameType := list.ServerNameList[0].NameType; nameType != 0x00 {
		return 0, fmt.Errorf("tls.servername: Unsupported name type [%x]", nameType)
	}

	*sni = ServerNameExtension(list.ServerNameList[0].HostName)
	return read, nil
}

// struct {
//     NamedGroup group;
//     opaque key_exchange<1..2^16-1>;
// } KeyShareEntry;
//
// struct {
//     select (Handshake.msg_type) {
//         case client_hello:
//             KeyShareEntry client_shares<0..2^16-1>;
//
//         case hello_retry_request:
//             NamedGroup selected_group;
//
//         case server_hello:
//             KeyShareEntry server_share;
//     };
// } KeyShare;
type KeyShareEntry struct {
	Group       NamedGroup
	KeyExchange []byte `tls:"head=2,min=1"`
}

func (kse KeyShareEntry) SizeValid() bool {
	return len(kse.KeyExchange) == keyExchangeSizeFromNamedGroup(kse.Group)
}

type KeyShareExtension struct {
	HandshakeType HandshakeType
	SelectedGroup NamedGroup
	Shares        []KeyShareEntry
}

type KeyShareClientHelloInner struct {
	ClientShares []KeyShareEntry `tls:"head=2,min=0"`
}
type KeyShareHelloRetryInner struct {
	SelectedGroup NamedGroup
}
type KeyShareServerHelloInner struct {
	ServerShare KeyShareEntry
}

func (ks KeyShareExtension) Type() ExtensionType {
	return ExtensionTypeKeyShare
}

func (ks KeyShareExtension) Marshal() ([]byte, error) {
	switch ks.HandshakeType {
	case HandshakeTypeClientHello:
		for _, share := range ks.Shares {
			if !share.SizeValid() {
				return nil, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
			}
		}
		return syntax.Marshal(KeyShareClientHelloInner{ks.Shares})

	case HandshakeTypeHelloRetryRequest:
		if len(ks.Shares) > 0 {
			return nil, fmt.Errorf("tls.keyshare: Key shares not allowed for HelloRetryRequest")
		}

		return syntax.Marshal(KeyShareHelloRetryInner{ks.SelectedGroup})

	case HandshakeTypeServerHello:
		if len(ks.Shares) != 1 {
			return nil, fmt.Errorf("tls.keyshare: Server must send exactly one key share")
		}

		if !ks.Shares[0].SizeValid() {
			return nil, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
		}

		return syntax.Marshal(KeyShareServerHelloInner{ks.Shares[0]})

	default:
		return nil, fmt.Errorf("tls.keyshare: Handshake type not allowed")
	}
}

func (ks *KeyShareExtension) Unmarshal(data []byte) (int, error) {
	switch ks.HandshakeType {
	case HandshakeTypeClientHello:
		var inner KeyShareClientHelloInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		for _, share := range inner.ClientShares {
			if !share.SizeValid() {
				return 0, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
			}
		}

		ks.Shares = inner.ClientShares
		return read, nil

	case HandshakeTypeHelloRetryRequest:
		var inner KeyShareHelloRetryInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		ks.SelectedGroup = inner.SelectedGroup
		return read, nil

	case HandshakeTypeServerHello:
		var inner KeyShareServerHelloInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		if !inner.ServerShare.SizeValid() {
			return 0, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
		}

		ks.Shares = []KeyShareEntry{inner.ServerShare}
		return read, nil

	default:
		return 0, fmt.Errorf("tls.keyshare: Handshake type not allowed")
	}
}

// struct {
//     NamedGroup named_group_list<2..2^16-1>;
// } NamedGroupList;
type SupportedGroupsExtension struct {
	Groups []NamedGroup `tls:"head=2,min=2"`
}

func (sg SupportedGroupsExtension) Type() ExtensionType {
	return ExtensionTypeSupportedGroups
}

func (sg SupportedGroupsExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(sg)
}

func (sg *SupportedGroupsExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sg)
}

// struct {
//   SignatureScheme supported_signature_algorithms<2..2^16-2>;
// } SignatureSchemeList
type SignatureAlgorithmsExtension struct {
	Algorithms []SignatureScheme `tls:"head=2,min=2"`
}

func (sa SignatureAlgorithmsExtension) Type() ExtensionType {
	return ExtensionTypeSignatureAlgorithms
}

func (sa SignatureAlgorithmsExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(sa)
}

func (sa *SignatureAlgorithmsExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sa)
}

// struct {
//     opaque identity<1..2^16-1>;
//     uint32 obfuscated_ticket_age;
// } PskIdentity;
//
// opaque PskBinderEntry<32..255>;
//
// struct {
//     select (Handshake.msg_type) {
//         case client_hello:
//             PskIdentity identities<7..2^16-1>;
//             PskBinderEntry binders<33..2^16-1>;
//
//         case server_hello:
//             uint16 selected_identity;
//     };
//
// } PreSharedKeyExtension;
type PSKIdentity struct {
	Identity            []byte `tls:"head=2,min=1"`
	ObfuscatedTicketAge uint32
}

type PSKBinderEntry struct {
	Binder []byte `tls:"head=1,min=32"`
}

type PreSharedKeyExtension struct {
	HandshakeType    HandshakeType
	Identities       []PSKIdentity
	Binders          []PSKBinderEntry
	SelectedIdentity uint16
}

type preSharedKeyClientInner struct {
	Identities []PSKIdentity    `tls:"head=2,min=7"`
	Binders    []PSKBinderEntry `tls:"head=2,min=33"`
}

type preSharedKeyServerInner struct {
	SelectedIdentity uint16
}

func (psk PreSharedKeyExtension) Type() ExtensionType {
	return ExtensionTypePreSharedKey
}

func (psk PreSharedKeyExtension) Marshal() ([]byte, error) {
	switch psk.HandshakeType {
	case HandshakeTypeClientHello:
		return syntax.Marshal(preSharedKeyClientInner{
			Identities: psk.Identities,
			Binders:    psk.Binders,
		})

	case HandshakeTypeServerHello:
		if len(psk.Identities) > 0 || len(psk.Binders) > 0 {
			return nil, fmt.Errorf("tls.presharedkey: Server can only provide an index")
		}
		return syntax.Marshal(preSharedKeyServerInner{psk.SelectedIdentity})

	default:
		return nil, fmt.Errorf("tls.presharedkey: Handshake type not supported")
	}
}

func (psk *PreSharedKeyExtension) Unmarshal(data []byte) (int, error) {
	switch psk.HandshakeType {
	case HandshakeTypeClientHello:
		var inner preSharedKeyClientInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		if len(inner.Identities) != len(inner.Binders) {
			return 0, fmt.Errorf("Lengths of identities and binders not equal")
		}

		psk.Identities = inner.Identities
		psk.Binders = inner.Binders
		return read, nil

	case HandshakeTypeServerHello:
		var inner preSharedKeyServerInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		psk.SelectedIdentity = inner.SelectedIdentity
		return read, nil

	default:
		return 0, fmt.Errorf("tls.presharedkey: Handshake type not supported")
	}
}

func (psk PreSharedKeyExtension) HasIdentity(id []byte) ([]byte, bool) {
	for i, localID := range psk.Identities {
		if bytes.Equal(localID.Identity, id) {
			return psk.Binders[i].Binder, true
		}
	}
	return nil, false
}

// enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
//
// struct {
//     PskKeyExchangeMode ke_modes<1..255>;
// } PskKeyExchangeModes;
type PSKKeyExchangeModesExtension struct {
	KEModes []PSKKeyExchangeMode `tls:"head=1,min=1"`
}

func (pkem PSKKeyExchangeModesExtension) Type() ExtensionType {
	return ExtensionTypePSKKeyExchangeModes
}

func (pkem PSKKeyExchangeModesExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(pkem)
}

func (pkem *PSKKeyExchangeModesExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, pkem)
}

// struct {
// } EarlyDataIndication;

type EarlyDataExtension struct{}

func (ed EarlyDataExtension) Type() ExtensionType {
	return ExtensionTypeEarlyData
}

func (ed EarlyDataExtension) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (ed *EarlyDataExtension) Unmarshal(data []byte) (int, error) {
	return 0, nil
}

// struct {
//     uint32 max_early_data_size;
// } TicketEarlyDataInfo;

type TicketEarlyDataInfoExtension struct {
	MaxEarlyDataSize uint32
}

func (tedi TicketEarlyDataInfoExtension) Type() ExtensionType {
	return ExtensionTypeTicketEarlyDataInfo
}

func (tedi TicketEarlyDataInfoExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(tedi)
}

func (tedi *TicketEarlyDataInfoExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, tedi)
}

// opaque ProtocolName<1..2^8-1>;
//
// struct {
//     ProtocolName protocol_name_list<2..2^16-1>
// } ProtocolNameList;
type ALPNExtension struct {
	Protocols []string
}

type protocolNameInner struct {
	Name []byte `tls:"head=1,min=1"`
}

type alpnExtensionInner struct {
	Protocols []protocolNameInner `tls:"head=2,min=2"`
}

func (alpn ALPNExtension) Type() ExtensionType {
	return ExtensionTypeALPN
}

func (alpn ALPNExtension) Marshal() ([]byte, error) {
	protocols := make([]protocolNameInner, len(alpn.Protocols))
	for i, protocol := range alpn.Protocols {
		protocols[i] = protocolNameInner{[]byte(protocol)}
	}
	return syntax.Marshal(alpnExtensionInner{protocols})
}

func (alpn *ALPNExtension) Unmarshal(data []byte) (int, error) {
	var inner alpnExtensionInner
	read, err := syntax.Unmarshal(data, &inner)

	if err != nil {
		return 0, err
	}

	alpn.Protocols = make([]string, len(inner.Protocols))
	for i, protocol := range inner.Protocols {
		alpn.Protocols[i] = string(protocol.Name)
	}
	return read, nil
}

// struct {
//     ProtocolVersion versions<2..254>;
// } SupportedVersions;
type SupportedVersionsExtension struct {
	HandshakeType HandshakeType
	Versions      []uint16
}

type SupportedVersionsClientHelloInner struct {
	Versions []uint16 `tls:"head=1,min=2,max=254"`
}

type SupportedVersionsServerHelloInner struct {
	Version uint16
}

func (sv SupportedVersionsExtension) Type() ExtensionType {
	return ExtensionTypeSupportedVersions
}

func (sv SupportedVersionsExtension) Marshal() ([]byte, error) {
	switch sv.HandshakeType {
	case HandshakeTypeClientHello:
		return syntax.Marshal(SupportedVersionsClientHelloInner{sv.Versions})
	case HandshakeTypeServerHello, HandshakeTypeHelloRetryRequest:
		return syntax.Marshal(SupportedVersionsServerHelloInner{sv.Versions[0]})
	default:
		return nil, fmt.Errorf("tls.supported_versions: Handshake type not allowed")
	}
}

func (sv *SupportedVersionsExtension) Unmarshal(data []byte) (int, error) {
	switch sv.HandshakeType {
	case HandshakeTypeClientHello:
		var inner SupportedVersionsClientHelloInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}
		sv.Versions = inner.Versions
		return read, nil

	case HandshakeTypeServerHello, HandshakeTypeHelloRetryRequest:
		var inner SupportedVersionsServerHelloInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}
		sv.Versions = []uint16{inner.Version}
		return read, nil

	default:
		return 0, fmt.Errorf("tls.supported_versions: Handshake type not allowed")
	}
}

// struct {
//     opaque cookie<1..2^16-1>;
// } Cookie;
type CookieExtension struct {
	Cookie []byte `tls:"head=2,min=1"`
}

func (c CookieExtension) Type() ExtensionType {
	return ExtensionTypeCookie
}

func (c CookieExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(c)
}

func (c *CookieExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, c)
}
