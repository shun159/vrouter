package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	th "github.com/apache/thrift/lib/go/thrift"
)

type TSandeshProtocol struct {
	trans         th.TRichTransport
	origTransport th.TTransport
	cfg           *th.TConfiguration
	Buffer        [64]byte
	signedness    map[int16]bool
	is_signed     bool
}

type timeoutable interface {
	Timeout() bool
}

func NewTSandeshProtocolTransport(t th.TTransport) *TSandeshProtocol {
	return NewTSandeshProtocolConf(t, &th.TConfiguration{})
}

func NewTSandeshProtocolConf(t th.TTransport, conf *th.TConfiguration) *TSandeshProtocol {
	th.PropagateTConfiguration(t, conf)
	p := &TSandeshProtocol{
		origTransport: t,
		cfg:           conf,
	}
	if et, ok := t.(th.TRichTransport); ok {
		p.trans = et
	} else {
		p.trans = th.NewTRichTransport(t)
	}
	return p
}

func (p *TSandeshProtocol) GetProtocol(t th.TTransport) th.TProtocol {
	return NewTSandeshProtocolConf(t, p.cfg)
}

func (p *TSandeshProtocol) SetTConfiguration(conf *th.TConfiguration) {
	p.cfg = conf
}

/*
 * Writing Methods
 */

func (p *TSandeshProtocol) WriteStructBegin(ctx context.Context, name string) error {
	s, found := signedness(name)
	if !found {
		emsg := fmt.Sprintf("%s is unrecognised struct\n", name)
		err := errors.New(emsg)
		th.NewTProtocolException(err)
	}
	p.signedness = s

	if err := p.WriteI32(ctx, int32(len(name))); err != nil {
		return err
	}

	if _, err := p.trans.WriteString(name); err != nil {
		return err
	}

	return nil
}

func (p *TSandeshProtocol) WriteStructEnd(ctx context.Context) error {
	return p.WriteByte(ctx, th.STOP)
}

func (p *TSandeshProtocol) WriteFieldBegin(ctx context.Context, name string, typeId th.TType, id int16) error {
	if unsigned, found := p.signedness[id]; found {
		p.is_signed = unsigned
	} else {
		p.is_signed = false
	}

	typeId = translate_ttype_to_stype(typeId, p.is_signed)
	if err := p.WriteByte(ctx, int8(typeId)); err != nil {
		return err
	}
	if err := p.WriteI16(ctx, id); err != nil {
		return err
	}
	return nil
}

func (p *TSandeshProtocol) WriteListBegin(ctx context.Context, elemType th.TType, size int) error {
	elemType = translate_ttype_to_stype(elemType, p.is_signed)
	fmt.Printf("list: elemtype: %d size: %d\n", elemType, size)
	if err := p.WriteByte(ctx, int8(elemType)); err != nil {
		return err
	}
	if err := p.WriteI32(ctx, int32(size)); err != nil {
		return err
	}
	return nil
}

func (p *TSandeshProtocol) WriteBool(ctx context.Context, value bool) error {
	if value {
		return p.WriteByte(ctx, 1)
	}
	return p.WriteByte(ctx, 0)
}

func (p *TSandeshProtocol) WriteByte(ctx context.Context, value int8) error {
	err := p.trans.WriteByte(byte(value))
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteI16(ctx context.Context, value int16) error {
	value_bin := p.Buffer[0:2]
	binary.BigEndian.PutUint16(value_bin, uint16(value))
	_, err := p.trans.Write(value_bin)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteI32(ctx context.Context, value int32) error {
	value_bin := p.Buffer[0:4]
	binary.BigEndian.PutUint32(value_bin, uint32(value))
	_, err := p.trans.Write(value_bin)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteI64(ctx context.Context, value int64) error {
	value_bin := p.Buffer[0:8]
	binary.BigEndian.PutUint64(value_bin, uint64(value))
	_, err := p.trans.Write(value_bin)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteDouble(ctx context.Context, value float64) error {
	return p.WriteI64(ctx, int64(math.Float64bits(value)))
}

func (p *TSandeshProtocol) WriteString(ctx context.Context, value string) error {
	if err := p.WriteI32(ctx, int32(len(value))); err != nil {
		return err
	}
	_, err := p.trans.WriteString(value)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteBinary(ctx context.Context, value []byte) error {
	if err := p.WriteI32(ctx, int32(len(value))); err != nil {
		return err
	}
	_, err := p.trans.Write(value)
	return th.NewTProtocolException(err)
}

/*
 * Reading methods
 */

func (p *TSandeshProtocol) ReadStructBegin(ctx context.Context) (name string, err error) {
	return p.ReadString(ctx)
}

func (p *TSandeshProtocol) ReadStructEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) ReadFieldBegin(ctx context.Context) (name string, typeId th.TType, seqId int16, err error) {
	t, err := p.ReadByte(ctx)
	typeId = translate_stype_to_ttype(th.TType(t))
	if err != nil {
		return name, typeId, seqId, err
	}

	if typeId == th.STOP {
		return name, typeId, seqId, err
	}

	seqId, err = p.ReadI16(ctx)
	if err != nil {
		return name, typeId, seqId, err
	}

	return name, typeId, seqId, err
}

func (p *TSandeshProtocol) ReadListBegin(ctx context.Context) (elemType th.TType, size int, err error) {
	b, e := p.ReadByte(ctx)
	if e != nil {
		err = th.NewTProtocolException(e)
		return
	}
	elemType = translate_stype_to_ttype(th.TType(th.TType(b)))
	size32, e := p.ReadI32(ctx)
	if e != nil {
		err = th.NewTProtocolException(e)
		return
	}
	err = checkSizeForProtocol(size32, p.cfg)
	if err != nil {
		return
	}
	size = int(size32)

	return
}

func (p *TSandeshProtocol) ReadBool(ctx context.Context) (bool, error) {
	b, e := p.ReadByte(ctx)
	v := true
	if b != 1 {
		v = false
	}
	return v, e
}

func (p *TSandeshProtocol) ReadByte(ctx context.Context) (int8, error) {
	v, err := p.trans.ReadByte()
	return int8(v), err
}

func (p *TSandeshProtocol) ReadI16(ctx context.Context) (value int16, err error) {
	buf := p.Buffer[0:2]
	err = p.readAll(ctx, buf)
	value = int16(binary.BigEndian.Uint16(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadI32(ctx context.Context) (value int32, err error) {
	buf := p.Buffer[0:4]
	err = p.readAll(ctx, buf)
	value = int32(binary.BigEndian.Uint32(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadI64(ctx context.Context) (value int64, err error) {
	buf := p.Buffer[0:8]
	err = p.readAll(ctx, buf)
	value = int64(binary.BigEndian.Uint64(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadDouble(ctx context.Context) (value float64, err error) {
	buf := p.Buffer[0:8]
	err = p.readAll(ctx, buf)
	value = math.Float64frombits(binary.BigEndian.Uint64(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadString(ctx context.Context) (value string, err error) {
	size, err := p.ReadI32(ctx)
	if err != nil {
		return
	}
	err = checkSizeForProtocol(size, p.cfg)
	if err != nil {
		return
	}
	if size == 0 {
		return
	}
	if size < int32(len(p.Buffer)) {
		// Avoid allocation on small reads
		buf := p.Buffer[:size]
		read, e := io.ReadFull(p.trans, buf)
		return string(buf[:read]), th.NewTProtocolException(e)
	}

	return p.readStringBody(size)
}

func (p *TSandeshProtocol) ReadBinary(ctx context.Context) ([]byte, error) {
	size, e := p.ReadI32(ctx)
	if e != nil {
		return nil, e
	}
	if err := checkSizeForProtocol(size, p.cfg); err != nil {
		return nil, err
	}

	buf, err := safeReadBytes(size, p.trans)
	return buf, th.NewTProtocolException(err)
}

/*
 * Protocol helpers
 */

func (p *TSandeshProtocol) Flush(ctx context.Context) (err error) {
	return th.NewTProtocolException(p.trans.Flush(ctx))
}

func (p *TSandeshProtocol) Transport() th.TTransport {
	return p.origTransport
}

func (p *TSandeshProtocol) Skip(ctx context.Context, fieldType th.TType) (err error) {
	return th.SkipDefaultDepth(ctx, p, fieldType)
}

func (p *TSandeshProtocol) readStringBody(size int32) (value string, err error) {
	buf, err := safeReadBytes(size, p.trans)
	return string(buf), th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) readAll(ctx context.Context, buf []byte) (err error) {
	var read int
	_, deadlineSet := ctx.Deadline()
	for {
		read, err = io.ReadFull(p.trans, buf)
		if deadlineSet && read == 0 && isTimeoutError(err) && ctx.Err() == nil {
			// This is I/O timeout without anything read,
			// and we still have time left, keep retrying.
			continue
		}
		// For anything else, don't retry
		break
	}
	return th.NewTProtocolException(err)
}

func checkSizeForProtocol(size int32, cfg *th.TConfiguration) error {
	if size < 0 {
		return th.NewTProtocolExceptionWithType(
			th.NEGATIVE_SIZE,
			fmt.Errorf("negative size: %d", size),
		)
	}
	if size > cfg.GetMaxMessageSize() {
		return th.NewTProtocolExceptionWithType(
			th.SIZE_LIMIT,
			fmt.Errorf("size exceeded max allowed: %d", size),
		)
	}
	return nil
}

func isTimeoutError(err error) bool {
	var t timeoutable
	if errors.As(err, &t) {
		return t.Timeout()
	}
	return false
}

// This function is shared between TSandeshProtocol and TCompactProtocol.
//
// It tries to read size bytes from trans, in a way that prevents large
// allocations when size is insanely large (mostly caused by malformed message).
func safeReadBytes(size int32, trans io.Reader) ([]byte, error) {
	if size < 0 {
		return nil, nil
	}

	buf := new(bytes.Buffer)
	_, err := io.CopyN(buf, trans, int64(size))
	return buf.Bytes(), err
}

/*
 * Unused writing methods
 */

func (p *TSandeshProtocol) WriteMessageBegin(ctx context.Context, name string, typeId th.TMessageType, seqId int32) error {
	return nil
}

func (p *TSandeshProtocol) WriteMessageEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) WriteMapBegin(ctx context.Context, keyType th.TType, valueType th.TType, size int) error {
	return nil
}

func (p *TSandeshProtocol) WriteMapEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) WriteSetBegin(context.Context, th.TType, int) error {
	return nil
}

func (p *TSandeshProtocol) WriteSetEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) WriteFieldEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) WriteFieldStop(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) WriteListEnd(ctx context.Context) error {
	return nil
}

/*
 * Unused reading methods
 */

func (p *TSandeshProtocol) ReadMessageBegin(ctx context.Context) (name string, typeId th.TMessageType, seqId int32, err error) {
	return
}

func (p *TSandeshProtocol) ReadMessageEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) ReadFieldEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) ReadMapBegin(ctx context.Context) (kType, vType th.TType, size int, err error) {
	return
}

func (p *TSandeshProtocol) ReadMapEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) ReadListEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) ReadSetBegin(ctx context.Context) (elemType th.TType, size int, err error) {
	return
}

func (p *TSandeshProtocol) ReadSetEnd(ctx context.Context) error {
	return nil
}

var SIGNEDNESS = map[string]map[int16]bool{
	"sandesh_hdr": {
		1: false,
		2: false,
	},

	"vr_nexthop_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: true,
		11: true,
		12: false,
		13: false,
		14: false,
		15: false,
		16: true,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: true,
		30: false,
	},

	"vr_interface_req": {
		1:  false,
		2:  true,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
		34: false,
		35: false,
		36: false,
		37: false,
		38: false,
		39: true,
		40: true,
		41: true,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
		48: false,
		49: false,
		50: false,
		51: false,
		52: false,
		53: false,
		54: false,
		55: false,
		56: false,
		57: false,
		58: true,
		59: false,
		60: true,
		61: false,
		62: false,
		63: false,
		64: false,
		65: true,
		66: true,
		67: true,
		68: true,
		77: true,
		78: true,
		79: false,
		80: false,
		81: true,
		82: true,
		83: false,
		84: false,
		85: false,
		86: false,
		87: false,
		88: false,
		89: false,
		90: false,
		91: true,
		92: false,
		93: true,
	},

	"vr_vxlan_req": {
		1: false,
		2: false,
		3: false,
		4: false,
	},

	"vr_route_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
	},

	"vr_mpls_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
	},

	"vr_mirror_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
		8: false,
		9: false,
	},

	"vr_vrf_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
	},

	"vr_flow_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  true,
		9:  true,
		10: true,
		11: true,
		12: true,
		13: true,
		14: false,
		15: true,
		16: true,
		17: true,
		18: true,
		19: true,
		20: true,
		21: false,
		22: true,
		23: true,
		24: true,
		25: true,
		26: true,
		27: false,
		28: true,
		29: true,
		30: true,
		31: true,
		32: true,
		33: true,
		34: true,
		35: true,
		36: false,
		37: false,
		38: false,
		39: false,
	},

	"vr_vrf_assign_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
	},

	"vr_vrf_stats_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
	},

	"vr_response": {
		1: false,
		2: false,
	},

	"vrouter_ops": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: true,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: true,
		31: true,
		32: true,
		33: true,
		34: false,
		35: false,
		36: false,
		37: false,
		38: true,
		39: false,
		40: false,
		41: false,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
	},

	"vr_mem_stats_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
		34: false,
		35: false,
		36: false,
		37: false,
		38: false,
		39: false,
		40: false,
		41: false,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
		48: false,
		49: false,
		50: false,
		51: false,
		52: false,
		53: false,
		54: false,
		55: false,
		56: false,
		57: false,
		58: false,
		59: false,
		60: false,
		61: false,
		62: false,
		63: false,
		64: false,
		65: false,
		66: false,
		67: false,
		68: false,
		69: false,
		70: false,
		71: false,
		72: false,
	},

	"vr_info_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
		8: false,
		9: false,
	},

	"vr_pkt_drop_log_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
	},

	"vr_drop_stats_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
		34: false,
		35: false,
		36: false,
		37: false,
		38: false,
		39: false,
		40: false,
		41: false,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
		48: false,
		49: false,
		50: false,
		51: false,
		52: false,
		53: false,
		54: false,
		55: false,
		56: false,
		57: false,
		58: false,
	},

	"vr_qos_map_req": {
		1:  false,
		2:  true,
		3:  true,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
	},

	"vr_fc_map_req": {
		1: false,
		2: true,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
		8: false,
	},

	"vr_flow_response": {
		1: false,
		2: true,
		3: true,
		4: true,
		5: true,
		6: true,
		7: true,
		8: false,
	},

	"vr_flow_table_data": {
		1:  false,
		2:  true,
		3:  true,
		4:  true,
		5:  false,
		6:  true,
		7:  true,
		8:  true,
		9:  true,
		10: true,
		11: true,
		12: true,
		13: true,
		14: true,
		15: true,
		16: true,
		17: true,
	},

	"vr_bridge_table_data": {
		1: false,
		2: true,
		3: true,
		4: true,
		5: false,
	},

	"vr_hugepage_config": {
		1: false,
		2: true,
		3: true,
		4: true,
		5: true,
		6: false,
		7: true,
	},
}

const (
	STOP     = 0
	VOID     = 1
	BOOL     = 2
	BYTE     = 3
	I08      = 3
	DOUBLE   = 4
	I16      = 6
	I32      = 8
	T_U64    = 9
	I64      = 10
	STRING   = 11
	UTF7     = 11
	STRUCT   = 12
	MAP      = 13
	SET      = 14
	LIST     = 15
	UTF8     = 16
	UTF16    = 17
	T_U16    = 19
	T_U32    = 20
	T_XML    = 21
	T_IPV4   = 22
	T_UUID   = 23
	T_IPADDR = 24
)

func signedness(st_name string) (map[int16]bool, bool) {
	if v, ok := SIGNEDNESS[st_name]; ok {
		return v, ok
	} else {
		return make(map[int16]bool), false
	}
}

func translate_ttype_to_stype(ttype th.TType, unsigned bool) th.TType {
	if ttype == I16 && unsigned {
		return T_U16
	} else if ttype == I32 && unsigned {
		return T_U32
	} else if ttype == I64 && unsigned {
		return T_U64
	} else {
		return ttype
	}
}

func translate_stype_to_ttype(ttype th.TType) th.TType {
	switch ttype {
	case T_U16:
		return I16
	case T_U32:
		return I32
	case T_U64:
		return I64
	default:
		return ttype
	}
}
