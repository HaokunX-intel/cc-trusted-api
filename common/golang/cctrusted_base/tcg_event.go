package cctrusted_base

import "log"

var _ FormatedTcgEvent = (*TcgImrEvent)(nil)

type TcgImrEvent struct {
	ImrIndex   uint32
	EventType  TcgEventType
	Digests    []TcgDigest
	EventSize  uint32
	Event      []byte
	FormatType TcgEventFormat
}

// GetDigests implements FormatedTcgEvent.
func (e *TcgImrEvent) GetDigests() []TcgDigest {
	return e.Digests
}

// GetEventType implements FormatedTcgEvent.
func (e *TcgImrEvent) GetEventType() TcgEventType {
	return e.EventType
}

// GetImrIndex implements FormatedTcgEvent.
func (e *TcgImrEvent) GetImrIndex() uint32 {
	return e.ImrIndex
}

// FormatType implements FormatedTcgEvent.
func (e *TcgImrEvent) GetFormatType() TcgEventFormat {
	return e.FormatType
}

// Dump implements FormatedTcgEvent.
func (e *TcgImrEvent) Dump() {
	l := log.Default()
	l.Println("----------------------------------Event Log Entry---------------------------------")
	l.Printf("IMR               : %d\n", e.ImrIndex)
	l.Printf("Type              : 0x%X (%v)\n", uint32(e.EventType), e.EventType)
	count := 0
	for _, digest := range e.Digests {
		l.Printf("Algorithm_id[%d]   : %d (%v) \n", count, digest.AlgID, digest.AlgID)
		l.Printf("Digest[%d]:\n", count)
		digestBlob := NewBinaryBlob(digest.Hash, 0)
		digestBlob.Dump()
		count += 1
	}
	l.Println("Event:")
	eventBlob := NewBinaryBlob(e.Event, 0)
	eventBlob.Dump()
}

var _ FormatedTcgEvent = (*TcgPcClientImrEvent)(nil)

type TcgPcClientImrEvent struct {
	ImrIndex      uint32
	EventType     TcgEventType
	Digest        [20]byte
	EventDataSize uint32
	Event         []byte
	FormatType    TcgEventFormat
}

// GetDigests implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetDigests() []TcgDigest {
	return nil
}

// GetEventType implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetEventType() TcgEventType {
	return e.EventType
}

// GetImrIndex implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetImrIndex() uint32 {
	return e.ImrIndex
}

// FormatType implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetFormatType() TcgEventFormat {
	return e.FormatType
}

// Dump implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) Dump() {
	l := log.Default()
	l.Println("--------------------Header Specification ID Event--------------------------")
	l.Printf("IMR               : %d\n", e.ImrIndex)
	l.Printf("Type              : 0x%X (%v) \n", uint32(e.EventType), e.EventType)
	l.Println("Digest:")
	digestBlob := NewBinaryBlob(e.Digest[:], 0)
	digestBlob.Dump()
	l.Println("Event:")
	eventBlob := NewBinaryBlob(e.Event, 0)
	eventBlob.Dump()
}

var _ FormatedTcgEvent = (*TcgTpmCelEventTLV)(nil)

type TcgTpmCelEventTLV struct {
	RecNum   TcgTLV
	Digests  TcgTLV
	Content  TcgTLV
	ImrIndex *TcgTLV
	NvIndex  *TcgTLV
}

func NewTcgTpmCelEventTLV(
	recNum int, digests []TcgDigest,
	isImr bool, imr int, nvIndex int,
	contentType TcgCelType, contentData TcgTpmsEvent,
) *TcgTpmCelEventTLV {
	p := &TcgTpmCelEventTLV{}

	p.RecNum = TcgTLV{
		Type:   uint32(CEL_SEQNUM),
		ValInt: recNum,
	}

	p.Digests = TcgTLV{
		Type:       uint32(CEL_DIGESTS),
		ValTcgTLVs: make([]TcgTLV, 0),
	}
	for _, d := range digests {
		val := TcgTLV{
			Type:     uint32(d.AlgID),
			ValBytes: d.Hash,
		}
		p.Digests.ValTcgTLVs = append(p.Digests.ValTcgTLVs, val)
	}

	p.Content = TcgTLV{
		Type:       uint32(contentType),
		ValTcgTLVs: contentData.ToTLV(),
	}

	if isImr {
		p.ImrIndex = &TcgTLV{
			Type:   uint32(CEL_PCR),
			ValInt: imr,
		}
	} else {
		p.NvIndex = &TcgTLV{
			Type:   uint32(CEL_NV_INDEX),
			ValInt: nvIndex,
		}
	}

	return p
}

// Dump implements FormatedTcgEvent.
func (t *TcgTpmCelEventTLV) Dump() {
	log := log.Default()

	log.Println("-----------------------------Canonical Event Log Entry----------------------------")
	log.Println("Encoding          : TLV")
	log.Printf("Rec Num           : %d\n", t.RecNum.ValInt)
	if t.ImrIndex != nil {
		log.Printf("IMR               : %d\n", t.ImrIndex.ValInt)
	}
	if t.NvIndex != nil {
		log.Printf("NvIndex           : %d\n", t.NvIndex.ValInt)
	}
	log.Printf("Type              : 0x%X (%v)\n", t.Content.Type, TcgCelType(t.Content.Type))

	log.Println("Digests:")
	for count, tlv := range t.Digests.ValTcgTLVs {
		log.Printf("Algorithm_id[%d]   : %d (%v)\n", count, tlv.Type, TCG_ALG(tlv.Type))
		log.Printf("Digest[%d]:\n", count)
		blob := NewBinaryBlob(tlv.ValBytes, 0)
		blob.Dump()
	}

	log.Println("Contents:")
	for count, tlv := range t.Content.ValTcgTLVs {
		switch tlv.ContentType {
		case ImaTemplate:
			t := TcgCelImaTemplateType(tlv.Type)
			if t == IMA_TEMPLATE_NAME {
				log.Printf("%d: %v = %v", count, t, tlv.ValString)
			} else if t == IMA_TEMPLATE_DATA {
				log.Printf("%d: %v = %v", count, t, tlv.ValBytes)
			}
		case PcClientStd:
			t := TcgCelPcClientStdType(tlv.Type)
			if t == PCCLIENT_STD_TYPE {
				log.Printf("%d: %v = %v", count, t, tlv.ValEventType)
			} else if t == PCCLIENT_STD_CONTENT {
				log.Printf("%d: %v = %v", count, t, tlv.ValBytes)
			}
		}
	}
}

// GetDigests implements FormatedTcgEvent.
func (t *TcgTpmCelEventTLV) GetDigests() []TcgDigest {
	ret := make([]TcgDigest, 0)

	for _, tlv := range t.Digests.ValTcgTLVs {
		ret = append(ret, TcgDigest{
			AlgID: TCG_ALG(tlv.Type),
			Hash:  tlv.ValBytes,
		})
	}

	return ret
}

// GetEventType implements FormatedTcgEvent.
func (t *TcgTpmCelEventTLV) GetEventType() TcgEventType {
	if t.Content.Type == uint32(CEL_IMA_TEMPLATE) {
		return IMA_MEASUREMENT_EVENT
	}

	if len(t.Content.ValTcgTLVs) >= 2 {
		return t.Content.ValTcgTLVs[1].ValEventType
	}
	// TODO: warning
	return EV_NO_ACTION
}

// GetFormatType implements FormatedTcgEvent.
func (t *TcgTpmCelEventTLV) GetFormatType() TcgEventFormat {
	return TCG_CEL_TLV
}

// GetImrIndex implements FormatedTcgEvent.
func (t *TcgTpmCelEventTLV) GetImrIndex() uint32 {
	if t.ImrIndex != nil {
		return uint32(t.ImrIndex.ValInt)
	}
	if t.NvIndex != nil {
		return uint32(t.NvIndex.ValInt)
	}
	// TODO: warning
	return 0
}

type TcgTpmsEventContetType string

const (
	ImaTemplate TcgTpmsEventContetType = "ImaTemplate"
	PcClientStd TcgTpmsEventContetType = "PcClientStd"
)

func (t TcgTpmsEventContetType) String() string {
	return string(t)
}

type TcgTLV struct {
	Type         uint32
	ValString    string
	ValInt       int
	ValBytes     []byte
	ValEventType TcgEventType
	ValTcgTLVs   []TcgTLV
	ContentType  TcgTpmsEventContetType
}

type TcgTpmsEvent interface {
	ToTLV() []TcgTLV
	// TODO: ToJSON() & ToCBOR()
}

var _ TcgTpmsEvent = (*TcgTpmsEventImaTemplate)(nil)

type TcgTpmsEventImaTemplate struct {
	Name string
	Data []byte
}

// ToTLV implements TcgTpmsEvent.
func (t *TcgTpmsEventImaTemplate) ToTLV() []TcgTLV {
	ret := make([]TcgTLV, 0)

	name := TcgTLV{
		Type:        uint32(IMA_TEMPLATE_NAME),
		ValString:   t.Name,
		ContentType: ImaTemplate,
	}
	ret = append(ret, name)

	data := TcgTLV{
		Type:        uint32(IMA_TEMPLATE_DATA),
		ValBytes:    t.Data,
		ContentType: ImaTemplate,
	}
	ret = append(ret, data)

	return ret
}

var _ TcgTpmsEvent = (*TcgTpmsEventPcClientStd)(nil)

type TcgTpmsEventPcClientStd struct {
	Type TcgEventType
	Data []byte
}

// ToTLV implements TcgTpmsEvent.
func (t *TcgTpmsEventPcClientStd) ToTLV() []TcgTLV {
	ret := make([]TcgTLV, 0)

	eventType := TcgTLV{
		Type:         uint32(PCCLIENT_STD_TYPE),
		ValEventType: t.Type,
		ContentType:  PcClientStd,
	}
	ret = append(ret, eventType)

	eventData := TcgTLV{
		Type:        uint32(PCCLIENT_STD_CONTENT),
		ValBytes:    t.Data,
		ContentType: PcClientStd,
	}
	ret = append(ret, eventData)

	return ret
}

func IsTcgTpmsCelEvent(event FormatedTcgEvent) bool {
	switch event.GetFormatType() {
	case TCG_CEL_TLV, TCG_CEL_JSON, TCG_CEL_CBOR:
		return true
	default:
		return false
	}
}
