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
	buffer        [64]byte
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

	if err := p.WriteString(ctx, name); err != nil {
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
	value_bin := p.buffer[0:2]
	binary.BigEndian.PutUint16(value_bin, uint16(value))
	_, err := p.trans.Write(value_bin)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteI32(ctx context.Context, value int32) error {
	value_bin := p.buffer[0:4]
	binary.BigEndian.PutUint32(value_bin, uint32(value))
	_, err := p.trans.Write(value_bin)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteI64(ctx context.Context, value int64) error {
	value_bin := p.buffer[0:8]
	binary.BigEndian.PutUint64(value_bin, uint64(value))
	_, err := p.trans.Write(value_bin)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteDouble(ctx context.Context, value float64) error {
	return p.WriteI64(ctx, int64(math.Float64bits(value)))
}

func (p *TSandeshProtocol) WriteString(ctx context.Context, value string) error {
	_, err := p.trans.WriteString(value)
	return th.NewTProtocolException(err)
}

func (p *TSandeshProtocol) WriteBinary(ctx context.Context, value []byte) error {
	_, err := p.trans.Write(value)
	return th.NewTProtocolException(err)
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

func (p *TSandeshProtocol) ReadStructBegin(ctx context.Context) (name string, err error) {
	return
}

func (p *TSandeshProtocol) ReadStructEnd(ctx context.Context) error {
	return nil
}

func (p *TSandeshProtocol) ReadFieldBegin(ctx context.Context) (name string, typeId th.TType, seqId int16, err error) {
	return
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

func (p *TSandeshProtocol) ReadListBegin(ctx context.Context) (elemType th.TType, size int, err error) {
	return
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

/*
 * Reading methods
 */

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
	buf := p.buffer[0:2]
	err = p.readAll(ctx, buf)
	value = int16(binary.BigEndian.Uint16(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadI32(ctx context.Context) (value int32, err error) {
	buf := p.buffer[0:4]
	err = p.readAll(ctx, buf)
	value = int32(binary.BigEndian.Uint32(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadI64(ctx context.Context) (value int64, err error) {
	buf := p.buffer[0:8]
	err = p.readAll(ctx, buf)
	value = int64(binary.BigEndian.Uint64(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadDouble(ctx context.Context) (value float64, err error) {
	buf := p.buffer[0:8]
	err = p.readAll(ctx, buf)
	value = math.Float64frombits(binary.BigEndian.Uint64(buf))
	return value, err
}

func (p *TSandeshProtocol) ReadString(ctx context.Context) (value string, err error) {
	size, e := p.ReadI32(ctx)
	if e != nil {
		return "", e
	}
	err = checkSizeForProtocol(size, p.cfg)
	if err != nil {
		return
	}
	if size == 0 {
		return "", nil
	}
	if size < int32(len(p.buffer)) {
		// Avoid allocation on small reads
		buf := p.buffer[:size]
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
