package cctrusted_base

type TCG_ALG uint32

const (
	TPM_ALG_ERROR  TCG_ALG = 0x0
	TPM_ALG_RSA    TCG_ALG = 0x1
	TPM_ALG_SHA1   TCG_ALG = 0x4
	TPM_ALG_SHA256 TCG_ALG = 0xB
	TPM_ALG_SHA384 TCG_ALG = 0xC
	TPM_ALG_SHA512 TCG_ALG = 0xD
	TPM_ALG_ECDSA  TCG_ALG = 0x18
)

func GetDefaultTPMAlg() TCG_ALG {
	return TPM_ALG_SHA384
}

func (alg TCG_ALG) String() string {
	switch alg {
	case TPM_ALG_ERROR:
		return "TPM_ALG_ERROR"
	case TPM_ALG_RSA:
		return "TPM_ALG_RSA"
	case TPM_ALG_SHA1:
		return "TPM_ALG_SHA1"
	case TPM_ALG_SHA256:
		return "TPM_ALG_SHA256"
	case TPM_ALG_SHA384:
		return "TPM_ALG_SHA384"
	case TPM_ALG_SHA512:
		return "TPM_ALG_SHA512"
	case TPM_ALG_ECDSA:
		return "TPM_ALG_ECDSA"
	}
	return ""
}

var (
	TPM_ALG_HASH_DIGEST_SIZE_TABLE = map[TCG_ALG]int{
		TPM_ALG_SHA1:   20,
		TPM_ALG_SHA256: 32,
		TPM_ALG_SHA384: 48,
		TPM_ALG_SHA512: 64,
	}
)

type TcgEventFormat string

const (
	TCG_PCCLIENT_FORMAT TcgEventFormat = "tcg_pcclient"
	TCG_CEL_TLV         TcgEventFormat = "tcg_cel_tlv"
	TCG_CEL_JSON        TcgEventFormat = "tcg_cel_json"
	TCG_CEL_CBOR        TcgEventFormat = "tcg_cel_cbor"
)

type TcgEventType uint32

const (
	EV_PREBOOT_CERT            TcgEventType = 0x0
	EV_POST_CODE               TcgEventType = 0x1
	EV_UNUSED                  TcgEventType = 0x2
	EV_NO_ACTION               TcgEventType = 0x3
	EV_SEPARATOR               TcgEventType = 0x4
	EV_ACTION                  TcgEventType = 0x5
	EV_EVENT_TAG               TcgEventType = 0x6
	EV_S_CRTM_CONTENTS         TcgEventType = 0x7
	EV_S_CRTM_VERSION          TcgEventType = 0x8
	EV_CPU_MICROCODE           TcgEventType = 0x9
	EV_PLATFORM_CONFIG_FLAGS   TcgEventType = 0xa
	EV_TABLE_OF_DEVICES        TcgEventType = 0xb
	EV_COMPACT_HASH            TcgEventType = 0xc
	EV_IPL                     TcgEventType = 0xd
	EV_IPL_PARTITION_DATA      TcgEventType = 0xe
	EV_NONHOST_CODE            TcgEventType = 0xf
	EV_NONHOST_CONFIG          TcgEventType = 0x10
	EV_NONHOST_INFO            TcgEventType = 0x11
	EV_OMIT_BOOT_DEVICE_EVENTS TcgEventType = 0x12
	EV_POST_CODE2              TcgEventType = 0x13
	// IMA event type defined aligned with MSFT
	IMA_MEASUREMENT_EVENT            TcgEventType = 0x14
	EV_EFI_EVENT_BASE                TcgEventType = 0x80000000
	EV_EFI_VARIABLE_DRIVER_CONFIG    TcgEventType = EV_EFI_EVENT_BASE + 0x1
	EV_EFI_VARIABLE_BOOT             TcgEventType = EV_EFI_EVENT_BASE + 0x2
	EV_EFI_BOOT_SERVICES_APPLICATION TcgEventType = EV_EFI_EVENT_BASE + 0x3
	EV_EFI_BOOT_SERVICES_DRIVER      TcgEventType = EV_EFI_EVENT_BASE + 0x4
	EV_EFI_RUNTIME_SERVICES_DRIVER   TcgEventType = EV_EFI_EVENT_BASE + 0x5
	EV_EFI_GPT_EVENT                 TcgEventType = EV_EFI_EVENT_BASE + 0x6
	EV_EFI_ACTION                    TcgEventType = EV_EFI_EVENT_BASE + 0x7
	EV_EFI_PLATFORM_FIRMWARE_BLOB    TcgEventType = EV_EFI_EVENT_BASE + 0x8
	EV_EFI_HANDOFF_TABLES            TcgEventType = EV_EFI_EVENT_BASE + 0x9
	EV_EFI_PLATFORM_FIRMWARE_BLOB2   TcgEventType = EV_EFI_EVENT_BASE + 0xa
	EV_EFI_HANDOFF_TABLES2           TcgEventType = EV_EFI_EVENT_BASE + 0xb
	EV_EFI_VARIABLE_BOOT2            TcgEventType = EV_EFI_EVENT_BASE + 0xc
	EV_EFI_GPT_EVENT2                TcgEventType = EV_EFI_EVENT_BASE + 0xd
	EV_EFI_HCRTM_EVENT               TcgEventType = EV_EFI_EVENT_BASE + 0x10
	EV_EFI_VARIABLE_AUTHORITY        TcgEventType = EV_EFI_EVENT_BASE + 0xe0
	EV_EFI_SPDM_FIRMWARE_BLOB        TcgEventType = EV_EFI_EVENT_BASE + 0xe1
	EV_EFI_SPDM_FIRMWARE_CONFIG      TcgEventType = EV_EFI_EVENT_BASE + 0xe2
	EV_EFI_SPDM_DEVICE_POLICY        TcgEventType = EV_EFI_EVENT_BASE + 0xe3
	EV_EFI_SPDM_DEVICE_AUTHORITY     TcgEventType = EV_EFI_EVENT_BASE + 0xe4
)

func (t TcgEventType) String() string {
	switch t {
	case EV_PREBOOT_CERT:
		return "EV_PREBOOT_CERT"
	case EV_POST_CODE:
		return "EV_POST_CODE"
	case EV_UNUSED:
		return "EV_UNUSED"
	case EV_NO_ACTION:
		return "EV_NO_ACTION"
	case EV_SEPARATOR:
		return "EV_SEPARATOR"
	case EV_ACTION:
		return "EV_ACTION"
	case EV_EVENT_TAG:
		return "EV_EVENT_TAG"
	case EV_S_CRTM_CONTENTS:
		return "EV_S_CRTM_CONTENTS"
	case EV_S_CRTM_VERSION:
		return "EV_S_CRTM_VERSION"
	case EV_CPU_MICROCODE:
		return "EV_CPU_MICROCODE"
	case EV_PLATFORM_CONFIG_FLAGS:
		return "EV_PLATFORM_CONFIG_FLAGS"
	case EV_TABLE_OF_DEVICES:
		return "EV_TABLE_OF_DEVICES"
	case EV_COMPACT_HASH:
		return "EV_COMPACT_HASH"
	case EV_IPL:
		return "EV_IPL"
	case EV_IPL_PARTITION_DATA:
		return "EV_IPL_PARTITION_DATA"
	case EV_NONHOST_CODE:
		return "EV_NONHOST_CODE"
	case EV_NONHOST_CONFIG:
		return "EV_NONHOST_CONFIG"
	case EV_NONHOST_INFO:
		return "EV_NONHOST_INFO"
	case EV_OMIT_BOOT_DEVICE_EVENTS:
		return "EV_OMIT_BOOT_DEVICE_EVENTS"
	case EV_POST_CODE2:
		return "EV_POST_CODE2"
	case IMA_MEASUREMENT_EVENT:
		return "IMA_MEASUREMENT_EVENT"
	case EV_EFI_EVENT_BASE:
		return "EV_EFI_EVENT_BASE"
	case EV_EFI_VARIABLE_DRIVER_CONFIG:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case EV_EFI_VARIABLE_BOOT:
		return "EV_EFI_VARIABLE_BOOT"
	case EV_EFI_BOOT_SERVICES_APPLICATION:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case EV_EFI_BOOT_SERVICES_DRIVER:
		return "EV_EFI_BOOT_SERVICES_DRIVER"
	case EV_EFI_RUNTIME_SERVICES_DRIVER:
		return "EV_EFI_RUNTIME_SERVICES_DRIVER"
	case EV_EFI_GPT_EVENT:
		return "EV_EFI_GPT_EVENT"
	case EV_EFI_ACTION:
		return "EV_EFI_ACTION"
	case EV_EFI_PLATFORM_FIRMWARE_BLOB:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB"
	case EV_EFI_HANDOFF_TABLES:
		return "EV_EFI_HANDOFF_TABLES"
	case EV_EFI_PLATFORM_FIRMWARE_BLOB2:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
	case EV_EFI_HANDOFF_TABLES2:
		return "EV_EFI_HANDOFF_TABLES2"
	case EV_EFI_VARIABLE_BOOT2:
		return "EV_EFI_VARIABLE_BOOT2"
	case EV_EFI_GPT_EVENT2:
		return "EV_EFI_GPT_EVENT2"
	case EV_EFI_HCRTM_EVENT:
		return "EV_EFI_HCRTM_EVENT"
	case EV_EFI_VARIABLE_AUTHORITY:
		return "EV_EFI_VARIABLE_AUTHORITY"
	case EV_EFI_SPDM_FIRMWARE_BLOB:
		return "EV_EFI_SPDM_FIRMWARE_BLOB"
	case EV_EFI_SPDM_FIRMWARE_CONFIG:
		return "EV_EFI_SPDM_FIRMWARE_CONFIG"
	case EV_EFI_SPDM_DEVICE_POLICY:
		return "EV_EFI_SPDM_DEVICE_POLICY"
	case EV_EFI_SPDM_DEVICE_AUTHORITY:
		return "EV_EFI_SPDM_DEVICE_AUTHORITY"
	}
	return ""
}

type TcgCelType uint32

const (
	// TCG CEL top level event types
	CEL_SEQNUM       TcgCelType = 0x00000000
	CEL_PCR          TcgCelType = 0x00000001
	CEL_NV_INDEX     TcgCelType = 0x00000002
	CEL_DIGESTS      TcgCelType = 0x00000003
	CEL_MGT          TcgCelType = 0x00000004
	CEL_PCCLIENT_STD TcgCelType = 0x00000005
	CEL_IMA_TEMPLATE TcgCelType = 0x00000007
	CEL_IMA_TLV      TcgCelType = 0x00000008
)

func (t TcgCelType) String() string {
	switch t {
	case CEL_SEQNUM:
		return "CEL_SEQNUM"
	case CEL_PCR:
		return "CEL_PCR"
	case CEL_NV_INDEX:
		return "CEL_NV_INDEX"
	case CEL_DIGESTS:
		return "CEL_DIGESTS"
	case CEL_MGT:
		return "CEL_MGT"
	case CEL_PCCLIENT_STD:
		return "CEL_PCCLIENT_STD"
	case CEL_IMA_TEMPLATE:
		return "CEL_IMA_TEMPLATE"
	case CEL_IMA_TLV:
		return "CEL_IMA_TLV"
	}

	return ""
}

type TcgCelMgtType uint32

const (
	CEL_MGT_TYPE                  TcgCelMgtType = 0
	CEL_MGT_DATA                  TcgCelMgtType = 1
	CEL_MGT_CEL_VERSION           TcgCelMgtType = 1
	CEL_MGT_CEL_VERSION_MAJOR     TcgCelMgtType = 0
	CEL_MGT_CEL_VERSION_MINOR     TcgCelMgtType = 1
	CEL_MGT_FIRMWARE_END          TcgCelMgtType = 2
	CEL_MGT_CEL_TIMESTAMP         TcgCelMgtType = 80
	CEL_MGT_STATE_TRANS           TcgCelMgtType = 81
	CEL_MGT_STATE_TRANS_SUSPEND   TcgCelMgtType = 0
	CEL_MGT_STATE_TRANS_HIBERNATE TcgCelMgtType = 1
	CEL_MGT_STATE_TRANS_KEXEC     TcgCelMgtType = 2
)

type TcgCelImaTLVType uint32

const (
	IMA_TLV_PATH      TcgCelImaTLVType = 0
	IMA_TLV_DATAHASH  TcgCelImaTLVType = 1
	IMA_TLV_DATASIG   TcgCelImaTLVType = 2
	IMA_TLV_OWNER     TcgCelImaTLVType = 3
	IMA_TLV_GROUP     TcgCelImaTLVType = 4
	IMA_TLV_MODE      TcgCelImaTLVType = 5
	IMA_TLV_TIMESTAMP TcgCelImaTLVType = 6
	IMA_TLV_LABEL     TcgCelImaTLVType = 7
)

func (t TcgCelImaTLVType) String() string {
	switch t {
	case IMA_TLV_PATH:
		return "IMA_TLV_PATH"
	case IMA_TLV_DATAHASH:
		return "IMA_TLV_DATAHASH"
	case IMA_TLV_DATASIG:
		return "IMA_TLV_DATASIG"
	case IMA_TLV_OWNER:
		return "IMA_TLV_OWNER"
	case IMA_TLV_GROUP:
		return "IMA_TLV_GROUP"
	case IMA_TLV_MODE:
		return "IMA_TLV_MODE"
	case IMA_TLV_TIMESTAMP:
		return "IMA_TLV_TIMESTAMP"
	case IMA_TLV_LABEL:
		return "IMA_TLV_LABEL"
	}
	return ""
}

type TcgCelImaTemplateType uint32

const (
	// IMA_TEMPLATE specific content types
	IMA_TEMPLATE_NAME TcgCelImaTemplateType = 0
	IMA_TEMPLATE_DATA TcgCelImaTemplateType = 1
)

func (t TcgCelImaTemplateType) String() string {
	switch t {
	case IMA_TEMPLATE_NAME:
		return "IMA_TEMPLATE_NAME"
	case IMA_TEMPLATE_DATA:
		return "IMA_TEMPLATE_DATA"
	}

	return ""
}

type TcgCelPcClientStdType uint32

const (
	// PCCLIENT_STD content types
	PCCLIENT_STD_TYPE    TcgCelPcClientStdType = 0
	PCCLIENT_STD_CONTENT TcgCelPcClientStdType = 1
)

func (t TcgCelPcClientStdType) String() string {
	switch t {
	case PCCLIENT_STD_TYPE:
		return "PCCLIENT_STD_TYPE"
	case PCCLIENT_STD_CONTENT:
		return "PCCLIENT_STD_CONTENT"
	}
	return ""
}

type FormatedTcgEvent interface {
	Dump()
	GetFormatType() TcgEventFormat
	GetImrIndex() uint32
	GetEventType() TcgEventType
	GetDigests() []TcgDigest
}
