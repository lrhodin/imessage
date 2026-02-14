package rustpushgo

// #include <rustpushgo.h>
// #cgo LDFLAGS: -L${SRCDIR}/../../ -lrustpushgo -ldl -lm -lz
// #cgo darwin LDFLAGS: -framework Security -framework SystemConfiguration -framework CoreFoundation -framework Foundation -framework CoreServices -lresolv
// #cgo linux LDFLAGS: -lpthread -lssl -lcrypto -lresolv
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"unsafe"
)

type RustBuffer struct {
	capacity C.int32_t
	len      C.int32_t
	data     *C.uint8_t
}

func rustBufferToC(rb RustBuffer) C.RustBuffer {
	return *(*C.RustBuffer)(unsafe.Pointer(&rb))
}

func rustBufferFromC(crb C.RustBuffer) RustBuffer {
	return *(*RustBuffer)(unsafe.Pointer(&crb))
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() int
	Capacity() int
}

func RustBufferFromExternal(b RustBufferI) RustBuffer {
	return RustBuffer{
		capacity: C.int(b.Capacity()),
		len:      C.int(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func (cb RustBuffer) Capacity() int {
	return int(cb.capacity)
}

func (cb RustBuffer) Len() int {
	return int(cb.len)
}

func (cb RustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.data)
}

func (cb RustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.data), C.int(cb.len))
	return bytes.NewReader(b)
}

func (cb RustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_rustpushgo_rustbuffer_free(rustBufferToC(cb), status)
		return false
	})
}

func (cb RustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.data), C.int(cb.len))
}

func stringToRustBuffer(str string) RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) RustBuffer {
	if len(b) == 0 {
		return RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) RustBuffer {
		return rustBufferFromC(C.ffi_rustpushgo_rustbuffer_from_bytes(foreign, status))
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) RustBuffer
}

type FfiConverter[GoType any, FfiType any] interface {
	Lift(value FfiType) GoType
	Lower(value GoType) FfiType
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

type FfiRustBufConverter[GoType any, FfiType any] interface {
	FfiConverter[GoType, FfiType]
	BufReader[GoType]
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[U any](converter BufLifter[error], callback func(*C.RustCallStatus) U) (U, error) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)

	return returnValue, err
}

func checkCallStatus(converter BufLifter[error], status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		return converter.Lift(rustBufferFromC(status.errorBuf))
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(rustBufferFromC(status.errorBuf))))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(rustBufferFromC(status.errorBuf))))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError(nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	(&FfiConverterCallbackInterfaceMessageCallback{}).register()
	(&FfiConverterCallbackInterfaceUpdateUsersCallback{}).register()
	uniffiInitContinuationCallback()
	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 24
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_rustpushgo_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("rustpushgo: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_connect(uniffiStatus)
		})
		if checksum != 48943 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_connect: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_create_config_from_hardware_key(uniffiStatus)
		})
		if checksum != 35117 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_create_config_from_hardware_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_create_config_from_hardware_key_with_device_id(uniffiStatus)
		})
		if checksum != 29425 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_create_config_from_hardware_key_with_device_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_create_local_macos_config(uniffiStatus)
		})
		if checksum != 37134 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_create_local_macos_config: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_create_local_macos_config_with_device_id(uniffiStatus)
		})
		if checksum != 44159 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_create_local_macos_config_with_device_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_init_logger(uniffiStatus)
		})
		if checksum != 38755 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_init_logger: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_login_start(uniffiStatus)
		})
		if checksum != 53356 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_login_start: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_new_client(uniffiStatus)
		})
		if checksum != 28402 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_new_client: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_func_restore_token_provider(uniffiStatus)
		})
		if checksum != 43442 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_func_restore_token_provider: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_cloud_diag_full_count(uniffiStatus)
		})
		if checksum != 27287 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_cloud_diag_full_count: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_cloud_download_attachment(uniffiStatus)
		})
		if checksum != 39378 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_cloud_download_attachment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_cloud_dump_chats_json(uniffiStatus)
		})
		if checksum != 18960 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_cloud_dump_chats_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_cloud_fetch_recent_messages(uniffiStatus)
		})
		if checksum != 26669 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_cloud_fetch_recent_messages: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_cloud_sync_attachments(uniffiStatus)
		})
		if checksum != 29066 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_cloud_sync_attachments: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_cloud_sync_chats(uniffiStatus)
		})
		if checksum != 48464 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_cloud_sync_chats: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_cloud_sync_messages(uniffiStatus)
		})
		if checksum != 61309 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_cloud_sync_messages: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_get_contacts_url(uniffiStatus)
		})
		if checksum != 50659 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_get_contacts_url: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_get_dsid(uniffiStatus)
		})
		if checksum != 24963 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_get_dsid: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_get_handles(uniffiStatus)
		})
		if checksum != 2965 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_get_handles: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_get_icloud_auth_headers(uniffiStatus)
		})
		if checksum != 46466 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_get_icloud_auth_headers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_attachment(uniffiStatus)
		})
		if checksum != 37459 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_attachment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_delivery_receipt(uniffiStatus)
		})
		if checksum != 54993 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_delivery_receipt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_edit(uniffiStatus)
		})
		if checksum != 50609 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_edit: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_message(uniffiStatus)
		})
		if checksum != 44502 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_message: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_read_receipt(uniffiStatus)
		})
		if checksum != 61662 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_read_receipt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_tapback(uniffiStatus)
		})
		if checksum != 6103 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_tapback: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_typing(uniffiStatus)
		})
		if checksum != 5805 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_typing: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_send_unsend(uniffiStatus)
		})
		if checksum != 29429 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_send_unsend: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_stop(uniffiStatus)
		})
		if checksum != 26750 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_stop: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_test_cloud_messages(uniffiStatus)
		})
		if checksum != 57936 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_test_cloud_messages: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_client_validate_targets(uniffiStatus)
		})
		if checksum != 44836 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_client_validate_targets: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_loginsession_finish(uniffiStatus)
		})
		if checksum != 25021 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_loginsession_finish: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_loginsession_needs_2fa(uniffiStatus)
		})
		if checksum != 10863 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_loginsession_needs_2fa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_loginsession_submit_2fa(uniffiStatus)
		})
		if checksum != 25146 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_loginsession_submit_2fa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedapsconnection_state(uniffiStatus)
		})
		if checksum != 755 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedapsconnection_state: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedapsstate_to_string(uniffiStatus)
		})
		if checksum != 2386 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedapsstate_to_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedidsngmidentity_to_string(uniffiStatus)
		})
		if checksum != 19097 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedidsngmidentity_to_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedidsusers_get_handles(uniffiStatus)
		})
		if checksum != 54112 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedidsusers_get_handles: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedidsusers_login_id(uniffiStatus)
		})
		if checksum != 23919 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedidsusers_login_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedidsusers_to_string(uniffiStatus)
		})
		if checksum != 29 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedidsusers_to_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedidsusers_validate_keystore(uniffiStatus)
		})
		if checksum != 49609 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedidsusers_validate_keystore: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedosconfig_get_device_id(uniffiStatus)
		})
		if checksum != 39645 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedosconfig_get_device_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_contacts_url(uniffiStatus)
		})
		if checksum != 29421 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_contacts_url: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_dsid(uniffiStatus)
		})
		if checksum != 58611 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_dsid: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_escrow_devices(uniffiStatus)
		})
		if checksum != 27126 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_escrow_devices: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_icloud_auth_headers(uniffiStatus)
		})
		if checksum != 3524 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_icloud_auth_headers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_mme_delegate_json(uniffiStatus)
		})
		if checksum != 9782 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_get_mme_delegate_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_join_keychain_clique(uniffiStatus)
		})
		if checksum != 14380 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_join_keychain_clique: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_join_keychain_clique_for_device(uniffiStatus)
		})
		if checksum != 59097 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_join_keychain_clique_for_device: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_wrappedtokenprovider_seed_mme_delegate_json(uniffiStatus)
		})
		if checksum != 6840 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_wrappedtokenprovider_seed_mme_delegate_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_constructor_wrappedapsstate_new(uniffiStatus)
		})
		if checksum != 9380 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_constructor_wrappedapsstate_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_constructor_wrappedidsngmidentity_new(uniffiStatus)
		})
		if checksum != 24162 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_constructor_wrappedidsngmidentity_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_constructor_wrappedidsusers_new(uniffiStatus)
		})
		if checksum != 42963 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_constructor_wrappedidsusers_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_messagecallback_on_message(uniffiStatus)
		})
		if checksum != 9227 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_messagecallback_on_message: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rustpushgo_checksum_method_updateuserscallback_update_users(uniffiStatus)
		})
		if checksum != 85 {
			// If this happens try cleaning and rebuilding your project
			panic("rustpushgo: uniffi_rustpushgo_checksum_method_updateuserscallback_update_users: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterInt32 struct{}

var FfiConverterInt32INSTANCE = FfiConverterInt32{}

func (FfiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (FfiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (FfiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (FfiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type FfiDestroyerInt32 struct{}

func (FfiDestroyerInt32) Destroy(_ int32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterInt64 struct{}

var FfiConverterInt64INSTANCE = FfiConverterInt64{}

func (FfiConverterInt64) Lower(value int64) C.int64_t {
	return C.int64_t(value)
}

func (FfiConverterInt64) Write(writer io.Writer, value int64) {
	writeInt64(writer, value)
}

func (FfiConverterInt64) Lift(value C.int64_t) int64 {
	return int64(value)
}

func (FfiConverterInt64) Read(reader io.Reader) int64 {
	return readInt64(reader)
}

type FfiDestroyerInt64 struct{}

func (FfiDestroyerInt64) Destroy(_ int64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct{}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct{}

func (FfiDestroyerBytes) Destroy(_ []byte) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	pointer      unsafe.Pointer
	callCounter  atomic.Int64
	freeFunction func(unsafe.Pointer, *C.RustCallStatus)
	destroyed    atomic.Bool
}

func newFfiObject(pointer unsafe.Pointer, freeFunction func(unsafe.Pointer, *C.RustCallStatus)) FfiObject {
	return FfiObject{
		pointer:      pointer,
		freeFunction: freeFunction,
	}
}

func (ffiObject *FfiObject) incrementPointer(debugName string) unsafe.Pointer {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return ffiObject.pointer
}

func (ffiObject *FfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject) freeRustArcPtr() {
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.pointer, status)
		return 0
	})
}

type Client struct {
	ffiObject FfiObject
}

func (_self *Client) CloudDiagFullCount() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_cloud_diag_full_count(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) CloudDownloadAttachment(recordName string) ([]byte, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_cloud_download_attachment(
				_pointer, rustBufferToC(FfiConverterStringINSTANCE.Lower(recordName)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterBytesINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) CloudDumpChatsJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_cloud_dump_chats_json(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) CloudFetchRecentMessages(sinceTimestampMs uint64, chatId *string, maxPages uint32, maxResults uint32) ([]WrappedCloudSyncMessage, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_cloud_fetch_recent_messages(
				_pointer, FfiConverterUint64INSTANCE.Lower(sinceTimestampMs), rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(chatId)), FfiConverterUint32INSTANCE.Lower(maxPages), FfiConverterUint32INSTANCE.Lower(maxResults),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterSequenceTypeWrappedCloudSyncMessageINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) CloudSyncAttachments(continuationToken *string) (WrappedCloudSyncAttachmentsPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_cloud_sync_attachments(
				_pointer, rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(continuationToken)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterTypeWrappedCloudSyncAttachmentsPageINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) CloudSyncChats(continuationToken *string) (WrappedCloudSyncChatsPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_cloud_sync_chats(
				_pointer, rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(continuationToken)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterTypeWrappedCloudSyncChatsPageINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) CloudSyncMessages(continuationToken *string) (WrappedCloudSyncMessagesPage, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_cloud_sync_messages(
				_pointer, rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(continuationToken)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterTypeWrappedCloudSyncMessagesPageINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) GetContactsUrl() (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_get_contacts_url(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterOptionalStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) GetDsid() (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_get_dsid(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterOptionalStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) GetHandles() []string {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithResult(func(status *C.RustCallStatus) *C.void {
		// rustFutureFunc
		return (*C.void)(C.uniffi_rustpushgo_fn_method_client_get_handles(
			_pointer,
			status,
		))
	},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterSequenceStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) GetIcloudAuthHeaders() (*map[string]string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_get_icloud_auth_headers(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterOptionalMapStringStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendAttachment(conversation WrappedConversation, data []byte, mime string, utiType string, filename string, handle string, replyGuid *string, replyPart *string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_attachment(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), rustBufferToC(FfiConverterBytesINSTANCE.Lower(data)), rustBufferToC(FfiConverterStringINSTANCE.Lower(mime)), rustBufferToC(FfiConverterStringINSTANCE.Lower(utiType)), rustBufferToC(FfiConverterStringINSTANCE.Lower(filename)), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)), rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(replyGuid)), rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(replyPart)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendDeliveryReceipt(conversation WrappedConversation, handle string) error {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithError(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_delivery_receipt(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_void(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) {
			// completeFunc
			C.ffi_rustpushgo_rust_future_complete_void(unsafe.Pointer(handle), status)
		},
		func(bool) {}, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_void(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendEdit(conversation WrappedConversation, targetUuid string, editPart uint64, newText string, handle string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_edit(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), rustBufferToC(FfiConverterStringINSTANCE.Lower(targetUuid)), FfiConverterUint64INSTANCE.Lower(editPart), rustBufferToC(FfiConverterStringINSTANCE.Lower(newText)), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendMessage(conversation WrappedConversation, text string, handle string, replyGuid *string, replyPart *string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_message(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), rustBufferToC(FfiConverterStringINSTANCE.Lower(text)), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)), rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(replyGuid)), rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(replyPart)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendReadReceipt(conversation WrappedConversation, handle string, forUuid *string) error {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithError(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_read_receipt(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)), rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(forUuid)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_void(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) {
			// completeFunc
			C.ffi_rustpushgo_rust_future_complete_void(unsafe.Pointer(handle), status)
		},
		func(bool) {}, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_void(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendTapback(conversation WrappedConversation, targetUuid string, targetPart uint64, reaction uint32, emoji *string, remove bool, handle string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_tapback(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), rustBufferToC(FfiConverterStringINSTANCE.Lower(targetUuid)), FfiConverterUint64INSTANCE.Lower(targetPart), FfiConverterUint32INSTANCE.Lower(reaction), rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(emoji)), FfiConverterBoolINSTANCE.Lower(remove), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendTyping(conversation WrappedConversation, typing bool, handle string) error {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithError(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_typing(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), FfiConverterBoolINSTANCE.Lower(typing), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_void(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) {
			// completeFunc
			C.ffi_rustpushgo_rust_future_complete_void(unsafe.Pointer(handle), status)
		},
		func(bool) {}, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_void(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) SendUnsend(conversation WrappedConversation, targetUuid string, editPart uint64, handle string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_send_unsend(
				_pointer, rustBufferToC(FfiConverterTypeWrappedConversationINSTANCE.Lower(conversation)), rustBufferToC(FfiConverterStringINSTANCE.Lower(targetUuid)), FfiConverterUint64INSTANCE.Lower(editPart), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) Stop() {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	uniffiRustCallAsync(func(status *C.RustCallStatus) *C.void {
		// rustFutureFunc
		return (*C.void)(C.uniffi_rustpushgo_fn_method_client_stop(
			_pointer,
			status,
		))
	},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_void(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) {
			// completeFunc
			C.ffi_rustpushgo_rust_future_complete_void(unsafe.Pointer(handle), status)
		},
		func(bool) {}, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_void(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) TestCloudMessages() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_client_test_cloud_messages(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *Client) ValidateTargets(targets []string, handle string) []string {
	_pointer := _self.ffiObject.incrementPointer("*Client")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithResult(func(status *C.RustCallStatus) *C.void {
		// rustFutureFunc
		return (*C.void)(C.uniffi_rustpushgo_fn_method_client_validate_targets(
			_pointer, rustBufferToC(FfiConverterSequenceStringINSTANCE.Lower(targets)), rustBufferToC(FfiConverterStringINSTANCE.Lower(handle)),
			status,
		))
	},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterSequenceStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (object *Client) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterClient struct{}

var FfiConverterClientINSTANCE = FfiConverterClient{}

func (c FfiConverterClient) Lift(pointer unsafe.Pointer) *Client {
	result := &Client{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_client(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*Client).Destroy)
	return result
}

func (c FfiConverterClient) Read(reader io.Reader) *Client {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterClient) Lower(value *Client) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*Client")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterClient) Write(writer io.Writer, value *Client) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerClient struct{}

func (_ FfiDestroyerClient) Destroy(value *Client) {
	value.Destroy()
}

type LoginSession struct {
	ffiObject FfiObject
}

func (_self *LoginSession) Finish(config *WrappedOsConfig, connection *WrappedApsConnection, existingIdentity **WrappedIdsngmIdentity, existingUsers **WrappedIdsUsers) (IdsUsersWithIdentityRecord, error) {
	_pointer := _self.ffiObject.incrementPointer("*LoginSession")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_loginsession_finish(
				_pointer, FfiConverterWrappedOSConfigINSTANCE.Lower(config), FfiConverterWrappedAPSConnectionINSTANCE.Lower(connection), rustBufferToC(FfiConverterOptionalWrappedIDSNGMIdentityINSTANCE.Lower(existingIdentity)), rustBufferToC(FfiConverterOptionalWrappedIDSUsersINSTANCE.Lower(existingUsers)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterTypeIDSUsersWithIdentityRecordINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *LoginSession) Needs2fa() bool {
	_pointer := _self.ffiObject.incrementPointer("*LoginSession")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rustpushgo_fn_method_loginsession_needs_2fa(
			_pointer, _uniffiStatus)
	}))
}

func (_self *LoginSession) Submit2fa(code string) (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*LoginSession")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_loginsession_submit_2fa(
				_pointer, rustBufferToC(FfiConverterStringINSTANCE.Lower(code)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_i8(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) C.int8_t {
			// completeFunc
			return C.ffi_rustpushgo_rust_future_complete_i8(unsafe.Pointer(handle), status)
		},
		FfiConverterBoolINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_i8(unsafe.Pointer(rustFuture), status)
		})
}

func (object *LoginSession) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterLoginSession struct{}

var FfiConverterLoginSessionINSTANCE = FfiConverterLoginSession{}

func (c FfiConverterLoginSession) Lift(pointer unsafe.Pointer) *LoginSession {
	result := &LoginSession{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_loginsession(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*LoginSession).Destroy)
	return result
}

func (c FfiConverterLoginSession) Read(reader io.Reader) *LoginSession {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterLoginSession) Lower(value *LoginSession) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*LoginSession")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterLoginSession) Write(writer io.Writer, value *LoginSession) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerLoginSession struct{}

func (_ FfiDestroyerLoginSession) Destroy(value *LoginSession) {
	value.Destroy()
}

type WrappedApsConnection struct {
	ffiObject FfiObject
}

func (_self *WrappedApsConnection) State() *WrappedApsState {
	_pointer := _self.ffiObject.incrementPointer("*WrappedApsConnection")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterWrappedAPSStateINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_method_wrappedapsconnection_state(
			_pointer, _uniffiStatus)
	}))
}

func (object *WrappedApsConnection) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterWrappedAPSConnection struct{}

var FfiConverterWrappedAPSConnectionINSTANCE = FfiConverterWrappedAPSConnection{}

func (c FfiConverterWrappedAPSConnection) Lift(pointer unsafe.Pointer) *WrappedApsConnection {
	result := &WrappedApsConnection{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_wrappedapsconnection(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*WrappedApsConnection).Destroy)
	return result
}

func (c FfiConverterWrappedAPSConnection) Read(reader io.Reader) *WrappedApsConnection {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterWrappedAPSConnection) Lower(value *WrappedApsConnection) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*WrappedApsConnection")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterWrappedAPSConnection) Write(writer io.Writer, value *WrappedApsConnection) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerWrappedApsConnection struct{}

func (_ FfiDestroyerWrappedApsConnection) Destroy(value *WrappedApsConnection) {
	value.Destroy()
}

type WrappedApsState struct {
	ffiObject FfiObject
}

func NewWrappedApsState(string *string) *WrappedApsState {
	return FfiConverterWrappedAPSStateINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_constructor_wrappedapsstate_new(rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(string)), _uniffiStatus)
	}))
}

func (_self *WrappedApsState) ToString() string {
	_pointer := _self.ffiObject.incrementPointer("*WrappedApsState")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return rustBufferFromC(C.uniffi_rustpushgo_fn_method_wrappedapsstate_to_string(
			_pointer, _uniffiStatus))
	}))
}

func (object *WrappedApsState) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterWrappedAPSState struct{}

var FfiConverterWrappedAPSStateINSTANCE = FfiConverterWrappedAPSState{}

func (c FfiConverterWrappedAPSState) Lift(pointer unsafe.Pointer) *WrappedApsState {
	result := &WrappedApsState{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_wrappedapsstate(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*WrappedApsState).Destroy)
	return result
}

func (c FfiConverterWrappedAPSState) Read(reader io.Reader) *WrappedApsState {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterWrappedAPSState) Lower(value *WrappedApsState) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*WrappedApsState")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterWrappedAPSState) Write(writer io.Writer, value *WrappedApsState) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerWrappedApsState struct{}

func (_ FfiDestroyerWrappedApsState) Destroy(value *WrappedApsState) {
	value.Destroy()
}

type WrappedIdsngmIdentity struct {
	ffiObject FfiObject
}

func NewWrappedIdsngmIdentity(string *string) *WrappedIdsngmIdentity {
	return FfiConverterWrappedIDSNGMIdentityINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_constructor_wrappedidsngmidentity_new(rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(string)), _uniffiStatus)
	}))
}

func (_self *WrappedIdsngmIdentity) ToString() string {
	_pointer := _self.ffiObject.incrementPointer("*WrappedIdsngmIdentity")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return rustBufferFromC(C.uniffi_rustpushgo_fn_method_wrappedidsngmidentity_to_string(
			_pointer, _uniffiStatus))
	}))
}

func (object *WrappedIdsngmIdentity) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterWrappedIDSNGMIdentity struct{}

var FfiConverterWrappedIDSNGMIdentityINSTANCE = FfiConverterWrappedIDSNGMIdentity{}

func (c FfiConverterWrappedIDSNGMIdentity) Lift(pointer unsafe.Pointer) *WrappedIdsngmIdentity {
	result := &WrappedIdsngmIdentity{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_wrappedidsngmidentity(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*WrappedIdsngmIdentity).Destroy)
	return result
}

func (c FfiConverterWrappedIDSNGMIdentity) Read(reader io.Reader) *WrappedIdsngmIdentity {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterWrappedIDSNGMIdentity) Lower(value *WrappedIdsngmIdentity) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*WrappedIdsngmIdentity")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterWrappedIDSNGMIdentity) Write(writer io.Writer, value *WrappedIdsngmIdentity) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerWrappedIdsngmIdentity struct{}

func (_ FfiDestroyerWrappedIdsngmIdentity) Destroy(value *WrappedIdsngmIdentity) {
	value.Destroy()
}

type WrappedIdsUsers struct {
	ffiObject FfiObject
}

func NewWrappedIdsUsers(string *string) *WrappedIdsUsers {
	return FfiConverterWrappedIDSUsersINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_constructor_wrappedidsusers_new(rustBufferToC(FfiConverterOptionalStringINSTANCE.Lower(string)), _uniffiStatus)
	}))
}

func (_self *WrappedIdsUsers) GetHandles() []string {
	_pointer := _self.ffiObject.incrementPointer("*WrappedIdsUsers")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSequenceStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return rustBufferFromC(C.uniffi_rustpushgo_fn_method_wrappedidsusers_get_handles(
			_pointer, _uniffiStatus))
	}))
}

func (_self *WrappedIdsUsers) LoginId(i uint64) string {
	_pointer := _self.ffiObject.incrementPointer("*WrappedIdsUsers")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return rustBufferFromC(C.uniffi_rustpushgo_fn_method_wrappedidsusers_login_id(
			_pointer, FfiConverterUint64INSTANCE.Lower(i), _uniffiStatus))
	}))
}

func (_self *WrappedIdsUsers) ToString() string {
	_pointer := _self.ffiObject.incrementPointer("*WrappedIdsUsers")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return rustBufferFromC(C.uniffi_rustpushgo_fn_method_wrappedidsusers_to_string(
			_pointer, _uniffiStatus))
	}))
}

func (_self *WrappedIdsUsers) ValidateKeystore() bool {
	_pointer := _self.ffiObject.incrementPointer("*WrappedIdsUsers")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rustpushgo_fn_method_wrappedidsusers_validate_keystore(
			_pointer, _uniffiStatus)
	}))
}

func (object *WrappedIdsUsers) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterWrappedIDSUsers struct{}

var FfiConverterWrappedIDSUsersINSTANCE = FfiConverterWrappedIDSUsers{}

func (c FfiConverterWrappedIDSUsers) Lift(pointer unsafe.Pointer) *WrappedIdsUsers {
	result := &WrappedIdsUsers{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_wrappedidsusers(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*WrappedIdsUsers).Destroy)
	return result
}

func (c FfiConverterWrappedIDSUsers) Read(reader io.Reader) *WrappedIdsUsers {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterWrappedIDSUsers) Lower(value *WrappedIdsUsers) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*WrappedIdsUsers")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterWrappedIDSUsers) Write(writer io.Writer, value *WrappedIdsUsers) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerWrappedIdsUsers struct{}

func (_ FfiDestroyerWrappedIdsUsers) Destroy(value *WrappedIdsUsers) {
	value.Destroy()
}

type WrappedOsConfig struct {
	ffiObject FfiObject
}

func (_self *WrappedOsConfig) GetDeviceId() string {
	_pointer := _self.ffiObject.incrementPointer("*WrappedOsConfig")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return rustBufferFromC(C.uniffi_rustpushgo_fn_method_wrappedosconfig_get_device_id(
			_pointer, _uniffiStatus))
	}))
}

func (object *WrappedOsConfig) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterWrappedOSConfig struct{}

var FfiConverterWrappedOSConfigINSTANCE = FfiConverterWrappedOSConfig{}

func (c FfiConverterWrappedOSConfig) Lift(pointer unsafe.Pointer) *WrappedOsConfig {
	result := &WrappedOsConfig{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_wrappedosconfig(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*WrappedOsConfig).Destroy)
	return result
}

func (c FfiConverterWrappedOSConfig) Read(reader io.Reader) *WrappedOsConfig {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterWrappedOSConfig) Lower(value *WrappedOsConfig) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*WrappedOsConfig")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterWrappedOSConfig) Write(writer io.Writer, value *WrappedOsConfig) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerWrappedOsConfig struct{}

func (_ FfiDestroyerWrappedOsConfig) Destroy(value *WrappedOsConfig) {
	value.Destroy()
}

type WrappedTokenProvider struct {
	ffiObject FfiObject
}

func (_self *WrappedTokenProvider) GetContactsUrl() (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_get_contacts_url(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterOptionalStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *WrappedTokenProvider) GetDsid() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_get_dsid(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *WrappedTokenProvider) GetEscrowDevices() ([]EscrowDeviceInfo, error) {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_get_escrow_devices(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterSequenceTypeEscrowDeviceInfoINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *WrappedTokenProvider) GetIcloudAuthHeaders() (map[string]string, error) {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_get_icloud_auth_headers(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterMapStringStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *WrappedTokenProvider) GetMmeDelegateJson() (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_get_mme_delegate_json(
				_pointer,
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterOptionalStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *WrappedTokenProvider) JoinKeychainClique(passcode string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_join_keychain_clique(
				_pointer, rustBufferToC(FfiConverterStringINSTANCE.Lower(passcode)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *WrappedTokenProvider) JoinKeychainCliqueForDevice(passcode string, deviceIndex uint32) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_join_keychain_clique_for_device(
				_pointer, rustBufferToC(FfiConverterStringINSTANCE.Lower(passcode)), FfiConverterUint32INSTANCE.Lower(deviceIndex),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_rust_buffer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) RustBufferI {
			// completeFunc
			return rustBufferFromC(C.ffi_rustpushgo_rust_future_complete_rust_buffer(unsafe.Pointer(handle), status))
		},
		FfiConverterStringINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_rust_buffer(unsafe.Pointer(rustFuture), status)
		})
}

func (_self *WrappedTokenProvider) SeedMmeDelegateJson(json string) error {
	_pointer := _self.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer _self.ffiObject.decrementPointer()
	return uniffiRustCallAsyncWithError(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_method_wrappedtokenprovider_seed_mme_delegate_json(
				_pointer, rustBufferToC(FfiConverterStringINSTANCE.Lower(json)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_void(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) {
			// completeFunc
			C.ffi_rustpushgo_rust_future_complete_void(unsafe.Pointer(handle), status)
		},
		func(bool) {}, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_void(unsafe.Pointer(rustFuture), status)
		})
}

func (object *WrappedTokenProvider) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterWrappedTokenProvider struct{}

var FfiConverterWrappedTokenProviderINSTANCE = FfiConverterWrappedTokenProvider{}

func (c FfiConverterWrappedTokenProvider) Lift(pointer unsafe.Pointer) *WrappedTokenProvider {
	result := &WrappedTokenProvider{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_rustpushgo_fn_free_wrappedtokenprovider(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*WrappedTokenProvider).Destroy)
	return result
}

func (c FfiConverterWrappedTokenProvider) Read(reader io.Reader) *WrappedTokenProvider {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterWrappedTokenProvider) Lower(value *WrappedTokenProvider) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*WrappedTokenProvider")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterWrappedTokenProvider) Write(writer io.Writer, value *WrappedTokenProvider) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerWrappedTokenProvider struct{}

func (_ FfiDestroyerWrappedTokenProvider) Destroy(value *WrappedTokenProvider) {
	value.Destroy()
}

type AccountPersistData struct {
	Username          string
	HashedPasswordHex string
	Pet               string
	Adsid             string
	Dsid              string
	SpdBase64         string
}

func (r *AccountPersistData) Destroy() {
	FfiDestroyerString{}.Destroy(r.Username)
	FfiDestroyerString{}.Destroy(r.HashedPasswordHex)
	FfiDestroyerString{}.Destroy(r.Pet)
	FfiDestroyerString{}.Destroy(r.Adsid)
	FfiDestroyerString{}.Destroy(r.Dsid)
	FfiDestroyerString{}.Destroy(r.SpdBase64)
}

type FfiConverterTypeAccountPersistData struct{}

var FfiConverterTypeAccountPersistDataINSTANCE = FfiConverterTypeAccountPersistData{}

func (c FfiConverterTypeAccountPersistData) Lift(rb RustBufferI) AccountPersistData {
	return LiftFromRustBuffer[AccountPersistData](c, rb)
}

func (c FfiConverterTypeAccountPersistData) Read(reader io.Reader) AccountPersistData {
	return AccountPersistData{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeAccountPersistData) Lower(value AccountPersistData) RustBuffer {
	return LowerIntoRustBuffer[AccountPersistData](c, value)
}

func (c FfiConverterTypeAccountPersistData) Write(writer io.Writer, value AccountPersistData) {
	FfiConverterStringINSTANCE.Write(writer, value.Username)
	FfiConverterStringINSTANCE.Write(writer, value.HashedPasswordHex)
	FfiConverterStringINSTANCE.Write(writer, value.Pet)
	FfiConverterStringINSTANCE.Write(writer, value.Adsid)
	FfiConverterStringINSTANCE.Write(writer, value.Dsid)
	FfiConverterStringINSTANCE.Write(writer, value.SpdBase64)
}

type FfiDestroyerTypeAccountPersistData struct{}

func (_ FfiDestroyerTypeAccountPersistData) Destroy(value AccountPersistData) {
	value.Destroy()
}

type EscrowDeviceInfo struct {
	Index       uint32
	DeviceName  string
	DeviceModel string
	Serial      string
	Timestamp   string
}

func (r *EscrowDeviceInfo) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.Index)
	FfiDestroyerString{}.Destroy(r.DeviceName)
	FfiDestroyerString{}.Destroy(r.DeviceModel)
	FfiDestroyerString{}.Destroy(r.Serial)
	FfiDestroyerString{}.Destroy(r.Timestamp)
}

type FfiConverterTypeEscrowDeviceInfo struct{}

var FfiConverterTypeEscrowDeviceInfoINSTANCE = FfiConverterTypeEscrowDeviceInfo{}

func (c FfiConverterTypeEscrowDeviceInfo) Lift(rb RustBufferI) EscrowDeviceInfo {
	return LiftFromRustBuffer[EscrowDeviceInfo](c, rb)
}

func (c FfiConverterTypeEscrowDeviceInfo) Read(reader io.Reader) EscrowDeviceInfo {
	return EscrowDeviceInfo{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeEscrowDeviceInfo) Lower(value EscrowDeviceInfo) RustBuffer {
	return LowerIntoRustBuffer[EscrowDeviceInfo](c, value)
}

func (c FfiConverterTypeEscrowDeviceInfo) Write(writer io.Writer, value EscrowDeviceInfo) {
	FfiConverterUint32INSTANCE.Write(writer, value.Index)
	FfiConverterStringINSTANCE.Write(writer, value.DeviceName)
	FfiConverterStringINSTANCE.Write(writer, value.DeviceModel)
	FfiConverterStringINSTANCE.Write(writer, value.Serial)
	FfiConverterStringINSTANCE.Write(writer, value.Timestamp)
}

type FfiDestroyerTypeEscrowDeviceInfo struct{}

func (_ FfiDestroyerTypeEscrowDeviceInfo) Destroy(value EscrowDeviceInfo) {
	value.Destroy()
}

type IdsUsersWithIdentityRecord struct {
	Users          *WrappedIdsUsers
	Identity       *WrappedIdsngmIdentity
	TokenProvider  **WrappedTokenProvider
	AccountPersist *AccountPersistData
}

func (r *IdsUsersWithIdentityRecord) Destroy() {
	FfiDestroyerWrappedIdsUsers{}.Destroy(r.Users)
	FfiDestroyerWrappedIdsngmIdentity{}.Destroy(r.Identity)
	FfiDestroyerOptionalWrappedTokenProvider{}.Destroy(r.TokenProvider)
	FfiDestroyerOptionalTypeAccountPersistData{}.Destroy(r.AccountPersist)
}

type FfiConverterTypeIDSUsersWithIdentityRecord struct{}

var FfiConverterTypeIDSUsersWithIdentityRecordINSTANCE = FfiConverterTypeIDSUsersWithIdentityRecord{}

func (c FfiConverterTypeIDSUsersWithIdentityRecord) Lift(rb RustBufferI) IdsUsersWithIdentityRecord {
	return LiftFromRustBuffer[IdsUsersWithIdentityRecord](c, rb)
}

func (c FfiConverterTypeIDSUsersWithIdentityRecord) Read(reader io.Reader) IdsUsersWithIdentityRecord {
	return IdsUsersWithIdentityRecord{
		FfiConverterWrappedIDSUsersINSTANCE.Read(reader),
		FfiConverterWrappedIDSNGMIdentityINSTANCE.Read(reader),
		FfiConverterOptionalWrappedTokenProviderINSTANCE.Read(reader),
		FfiConverterOptionalTypeAccountPersistDataINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeIDSUsersWithIdentityRecord) Lower(value IdsUsersWithIdentityRecord) RustBuffer {
	return LowerIntoRustBuffer[IdsUsersWithIdentityRecord](c, value)
}

func (c FfiConverterTypeIDSUsersWithIdentityRecord) Write(writer io.Writer, value IdsUsersWithIdentityRecord) {
	FfiConverterWrappedIDSUsersINSTANCE.Write(writer, value.Users)
	FfiConverterWrappedIDSNGMIdentityINSTANCE.Write(writer, value.Identity)
	FfiConverterOptionalWrappedTokenProviderINSTANCE.Write(writer, value.TokenProvider)
	FfiConverterOptionalTypeAccountPersistDataINSTANCE.Write(writer, value.AccountPersist)
}

type FfiDestroyerTypeIdsUsersWithIdentityRecord struct{}

func (_ FfiDestroyerTypeIdsUsersWithIdentityRecord) Destroy(value IdsUsersWithIdentityRecord) {
	value.Destroy()
}

type WrappedAttachment struct {
	MimeType   string
	Filename   string
	UtiType    string
	Size       uint64
	IsInline   bool
	InlineData *[]byte
}

func (r *WrappedAttachment) Destroy() {
	FfiDestroyerString{}.Destroy(r.MimeType)
	FfiDestroyerString{}.Destroy(r.Filename)
	FfiDestroyerString{}.Destroy(r.UtiType)
	FfiDestroyerUint64{}.Destroy(r.Size)
	FfiDestroyerBool{}.Destroy(r.IsInline)
	FfiDestroyerOptionalBytes{}.Destroy(r.InlineData)
}

type FfiConverterTypeWrappedAttachment struct{}

var FfiConverterTypeWrappedAttachmentINSTANCE = FfiConverterTypeWrappedAttachment{}

func (c FfiConverterTypeWrappedAttachment) Lift(rb RustBufferI) WrappedAttachment {
	return LiftFromRustBuffer[WrappedAttachment](c, rb)
}

func (c FfiConverterTypeWrappedAttachment) Read(reader io.Reader) WrappedAttachment {
	return WrappedAttachment{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedAttachment) Lower(value WrappedAttachment) RustBuffer {
	return LowerIntoRustBuffer[WrappedAttachment](c, value)
}

func (c FfiConverterTypeWrappedAttachment) Write(writer io.Writer, value WrappedAttachment) {
	FfiConverterStringINSTANCE.Write(writer, value.MimeType)
	FfiConverterStringINSTANCE.Write(writer, value.Filename)
	FfiConverterStringINSTANCE.Write(writer, value.UtiType)
	FfiConverterUint64INSTANCE.Write(writer, value.Size)
	FfiConverterBoolINSTANCE.Write(writer, value.IsInline)
	FfiConverterOptionalBytesINSTANCE.Write(writer, value.InlineData)
}

type FfiDestroyerTypeWrappedAttachment struct{}

func (_ FfiDestroyerTypeWrappedAttachment) Destroy(value WrappedAttachment) {
	value.Destroy()
}

type WrappedCloudAttachmentInfo struct {
	Guid       string
	MimeType   *string
	UtiType    *string
	Filename   *string
	FileSize   int64
	RecordName string
}

func (r *WrappedCloudAttachmentInfo) Destroy() {
	FfiDestroyerString{}.Destroy(r.Guid)
	FfiDestroyerOptionalString{}.Destroy(r.MimeType)
	FfiDestroyerOptionalString{}.Destroy(r.UtiType)
	FfiDestroyerOptionalString{}.Destroy(r.Filename)
	FfiDestroyerInt64{}.Destroy(r.FileSize)
	FfiDestroyerString{}.Destroy(r.RecordName)
}

type FfiConverterTypeWrappedCloudAttachmentInfo struct{}

var FfiConverterTypeWrappedCloudAttachmentInfoINSTANCE = FfiConverterTypeWrappedCloudAttachmentInfo{}

func (c FfiConverterTypeWrappedCloudAttachmentInfo) Lift(rb RustBufferI) WrappedCloudAttachmentInfo {
	return LiftFromRustBuffer[WrappedCloudAttachmentInfo](c, rb)
}

func (c FfiConverterTypeWrappedCloudAttachmentInfo) Read(reader io.Reader) WrappedCloudAttachmentInfo {
	return WrappedCloudAttachmentInfo{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedCloudAttachmentInfo) Lower(value WrappedCloudAttachmentInfo) RustBuffer {
	return LowerIntoRustBuffer[WrappedCloudAttachmentInfo](c, value)
}

func (c FfiConverterTypeWrappedCloudAttachmentInfo) Write(writer io.Writer, value WrappedCloudAttachmentInfo) {
	FfiConverterStringINSTANCE.Write(writer, value.Guid)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.MimeType)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.UtiType)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Filename)
	FfiConverterInt64INSTANCE.Write(writer, value.FileSize)
	FfiConverterStringINSTANCE.Write(writer, value.RecordName)
}

type FfiDestroyerTypeWrappedCloudAttachmentInfo struct{}

func (_ FfiDestroyerTypeWrappedCloudAttachmentInfo) Destroy(value WrappedCloudAttachmentInfo) {
	value.Destroy()
}

type WrappedCloudSyncAttachmentsPage struct {
	ContinuationToken *string
	Status            int32
	Done              bool
	Attachments       []WrappedCloudAttachmentInfo
}

func (r *WrappedCloudSyncAttachmentsPage) Destroy() {
	FfiDestroyerOptionalString{}.Destroy(r.ContinuationToken)
	FfiDestroyerInt32{}.Destroy(r.Status)
	FfiDestroyerBool{}.Destroy(r.Done)
	FfiDestroyerSequenceTypeWrappedCloudAttachmentInfo{}.Destroy(r.Attachments)
}

type FfiConverterTypeWrappedCloudSyncAttachmentsPage struct{}

var FfiConverterTypeWrappedCloudSyncAttachmentsPageINSTANCE = FfiConverterTypeWrappedCloudSyncAttachmentsPage{}

func (c FfiConverterTypeWrappedCloudSyncAttachmentsPage) Lift(rb RustBufferI) WrappedCloudSyncAttachmentsPage {
	return LiftFromRustBuffer[WrappedCloudSyncAttachmentsPage](c, rb)
}

func (c FfiConverterTypeWrappedCloudSyncAttachmentsPage) Read(reader io.Reader) WrappedCloudSyncAttachmentsPage {
	return WrappedCloudSyncAttachmentsPage{
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterInt32INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterSequenceTypeWrappedCloudAttachmentInfoINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedCloudSyncAttachmentsPage) Lower(value WrappedCloudSyncAttachmentsPage) RustBuffer {
	return LowerIntoRustBuffer[WrappedCloudSyncAttachmentsPage](c, value)
}

func (c FfiConverterTypeWrappedCloudSyncAttachmentsPage) Write(writer io.Writer, value WrappedCloudSyncAttachmentsPage) {
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ContinuationToken)
	FfiConverterInt32INSTANCE.Write(writer, value.Status)
	FfiConverterBoolINSTANCE.Write(writer, value.Done)
	FfiConverterSequenceTypeWrappedCloudAttachmentInfoINSTANCE.Write(writer, value.Attachments)
}

type FfiDestroyerTypeWrappedCloudSyncAttachmentsPage struct{}

func (_ FfiDestroyerTypeWrappedCloudSyncAttachmentsPage) Destroy(value WrappedCloudSyncAttachmentsPage) {
	value.Destroy()
}

type WrappedCloudSyncChat struct {
	RecordName         string
	CloudChatId        string
	GroupId            string
	Style              int64
	Service            string
	DisplayName        *string
	Participants       []string
	Deleted            bool
	UpdatedTimestampMs uint64
}

func (r *WrappedCloudSyncChat) Destroy() {
	FfiDestroyerString{}.Destroy(r.RecordName)
	FfiDestroyerString{}.Destroy(r.CloudChatId)
	FfiDestroyerString{}.Destroy(r.GroupId)
	FfiDestroyerInt64{}.Destroy(r.Style)
	FfiDestroyerString{}.Destroy(r.Service)
	FfiDestroyerOptionalString{}.Destroy(r.DisplayName)
	FfiDestroyerSequenceString{}.Destroy(r.Participants)
	FfiDestroyerBool{}.Destroy(r.Deleted)
	FfiDestroyerUint64{}.Destroy(r.UpdatedTimestampMs)
}

type FfiConverterTypeWrappedCloudSyncChat struct{}

var FfiConverterTypeWrappedCloudSyncChatINSTANCE = FfiConverterTypeWrappedCloudSyncChat{}

func (c FfiConverterTypeWrappedCloudSyncChat) Lift(rb RustBufferI) WrappedCloudSyncChat {
	return LiftFromRustBuffer[WrappedCloudSyncChat](c, rb)
}

func (c FfiConverterTypeWrappedCloudSyncChat) Read(reader io.Reader) WrappedCloudSyncChat {
	return WrappedCloudSyncChat{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedCloudSyncChat) Lower(value WrappedCloudSyncChat) RustBuffer {
	return LowerIntoRustBuffer[WrappedCloudSyncChat](c, value)
}

func (c FfiConverterTypeWrappedCloudSyncChat) Write(writer io.Writer, value WrappedCloudSyncChat) {
	FfiConverterStringINSTANCE.Write(writer, value.RecordName)
	FfiConverterStringINSTANCE.Write(writer, value.CloudChatId)
	FfiConverterStringINSTANCE.Write(writer, value.GroupId)
	FfiConverterInt64INSTANCE.Write(writer, value.Style)
	FfiConverterStringINSTANCE.Write(writer, value.Service)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.DisplayName)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.Participants)
	FfiConverterBoolINSTANCE.Write(writer, value.Deleted)
	FfiConverterUint64INSTANCE.Write(writer, value.UpdatedTimestampMs)
}

type FfiDestroyerTypeWrappedCloudSyncChat struct{}

func (_ FfiDestroyerTypeWrappedCloudSyncChat) Destroy(value WrappedCloudSyncChat) {
	value.Destroy()
}

type WrappedCloudSyncChatsPage struct {
	ContinuationToken *string
	Status            int32
	Done              bool
	Chats             []WrappedCloudSyncChat
}

func (r *WrappedCloudSyncChatsPage) Destroy() {
	FfiDestroyerOptionalString{}.Destroy(r.ContinuationToken)
	FfiDestroyerInt32{}.Destroy(r.Status)
	FfiDestroyerBool{}.Destroy(r.Done)
	FfiDestroyerSequenceTypeWrappedCloudSyncChat{}.Destroy(r.Chats)
}

type FfiConverterTypeWrappedCloudSyncChatsPage struct{}

var FfiConverterTypeWrappedCloudSyncChatsPageINSTANCE = FfiConverterTypeWrappedCloudSyncChatsPage{}

func (c FfiConverterTypeWrappedCloudSyncChatsPage) Lift(rb RustBufferI) WrappedCloudSyncChatsPage {
	return LiftFromRustBuffer[WrappedCloudSyncChatsPage](c, rb)
}

func (c FfiConverterTypeWrappedCloudSyncChatsPage) Read(reader io.Reader) WrappedCloudSyncChatsPage {
	return WrappedCloudSyncChatsPage{
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterInt32INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterSequenceTypeWrappedCloudSyncChatINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedCloudSyncChatsPage) Lower(value WrappedCloudSyncChatsPage) RustBuffer {
	return LowerIntoRustBuffer[WrappedCloudSyncChatsPage](c, value)
}

func (c FfiConverterTypeWrappedCloudSyncChatsPage) Write(writer io.Writer, value WrappedCloudSyncChatsPage) {
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ContinuationToken)
	FfiConverterInt32INSTANCE.Write(writer, value.Status)
	FfiConverterBoolINSTANCE.Write(writer, value.Done)
	FfiConverterSequenceTypeWrappedCloudSyncChatINSTANCE.Write(writer, value.Chats)
}

type FfiDestroyerTypeWrappedCloudSyncChatsPage struct{}

func (_ FfiDestroyerTypeWrappedCloudSyncChatsPage) Destroy(value WrappedCloudSyncChatsPage) {
	value.Destroy()
}

type WrappedCloudSyncMessage struct {
	RecordName        string
	Guid              string
	CloudChatId       string
	Sender            string
	IsFromMe          bool
	Text              *string
	Subject           *string
	Service           string
	TimestampMs       int64
	Deleted           bool
	TapbackType       *uint32
	TapbackTargetGuid *string
	TapbackEmoji      *string
	AttachmentGuids   []string
}

func (r *WrappedCloudSyncMessage) Destroy() {
	FfiDestroyerString{}.Destroy(r.RecordName)
	FfiDestroyerString{}.Destroy(r.Guid)
	FfiDestroyerString{}.Destroy(r.CloudChatId)
	FfiDestroyerString{}.Destroy(r.Sender)
	FfiDestroyerBool{}.Destroy(r.IsFromMe)
	FfiDestroyerOptionalString{}.Destroy(r.Text)
	FfiDestroyerOptionalString{}.Destroy(r.Subject)
	FfiDestroyerString{}.Destroy(r.Service)
	FfiDestroyerInt64{}.Destroy(r.TimestampMs)
	FfiDestroyerBool{}.Destroy(r.Deleted)
	FfiDestroyerOptionalUint32{}.Destroy(r.TapbackType)
	FfiDestroyerOptionalString{}.Destroy(r.TapbackTargetGuid)
	FfiDestroyerOptionalString{}.Destroy(r.TapbackEmoji)
	FfiDestroyerSequenceString{}.Destroy(r.AttachmentGuids)
}

type FfiConverterTypeWrappedCloudSyncMessage struct{}

var FfiConverterTypeWrappedCloudSyncMessageINSTANCE = FfiConverterTypeWrappedCloudSyncMessage{}

func (c FfiConverterTypeWrappedCloudSyncMessage) Lift(rb RustBufferI) WrappedCloudSyncMessage {
	return LiftFromRustBuffer[WrappedCloudSyncMessage](c, rb)
}

func (c FfiConverterTypeWrappedCloudSyncMessage) Read(reader io.Reader) WrappedCloudSyncMessage {
	return WrappedCloudSyncMessage{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalUint32INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedCloudSyncMessage) Lower(value WrappedCloudSyncMessage) RustBuffer {
	return LowerIntoRustBuffer[WrappedCloudSyncMessage](c, value)
}

func (c FfiConverterTypeWrappedCloudSyncMessage) Write(writer io.Writer, value WrappedCloudSyncMessage) {
	FfiConverterStringINSTANCE.Write(writer, value.RecordName)
	FfiConverterStringINSTANCE.Write(writer, value.Guid)
	FfiConverterStringINSTANCE.Write(writer, value.CloudChatId)
	FfiConverterStringINSTANCE.Write(writer, value.Sender)
	FfiConverterBoolINSTANCE.Write(writer, value.IsFromMe)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Text)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Subject)
	FfiConverterStringINSTANCE.Write(writer, value.Service)
	FfiConverterInt64INSTANCE.Write(writer, value.TimestampMs)
	FfiConverterBoolINSTANCE.Write(writer, value.Deleted)
	FfiConverterOptionalUint32INSTANCE.Write(writer, value.TapbackType)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.TapbackTargetGuid)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.TapbackEmoji)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.AttachmentGuids)
}

type FfiDestroyerTypeWrappedCloudSyncMessage struct{}

func (_ FfiDestroyerTypeWrappedCloudSyncMessage) Destroy(value WrappedCloudSyncMessage) {
	value.Destroy()
}

type WrappedCloudSyncMessagesPage struct {
	ContinuationToken *string
	Status            int32
	Done              bool
	Messages          []WrappedCloudSyncMessage
}

func (r *WrappedCloudSyncMessagesPage) Destroy() {
	FfiDestroyerOptionalString{}.Destroy(r.ContinuationToken)
	FfiDestroyerInt32{}.Destroy(r.Status)
	FfiDestroyerBool{}.Destroy(r.Done)
	FfiDestroyerSequenceTypeWrappedCloudSyncMessage{}.Destroy(r.Messages)
}

type FfiConverterTypeWrappedCloudSyncMessagesPage struct{}

var FfiConverterTypeWrappedCloudSyncMessagesPageINSTANCE = FfiConverterTypeWrappedCloudSyncMessagesPage{}

func (c FfiConverterTypeWrappedCloudSyncMessagesPage) Lift(rb RustBufferI) WrappedCloudSyncMessagesPage {
	return LiftFromRustBuffer[WrappedCloudSyncMessagesPage](c, rb)
}

func (c FfiConverterTypeWrappedCloudSyncMessagesPage) Read(reader io.Reader) WrappedCloudSyncMessagesPage {
	return WrappedCloudSyncMessagesPage{
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterInt32INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterSequenceTypeWrappedCloudSyncMessageINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedCloudSyncMessagesPage) Lower(value WrappedCloudSyncMessagesPage) RustBuffer {
	return LowerIntoRustBuffer[WrappedCloudSyncMessagesPage](c, value)
}

func (c FfiConverterTypeWrappedCloudSyncMessagesPage) Write(writer io.Writer, value WrappedCloudSyncMessagesPage) {
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ContinuationToken)
	FfiConverterInt32INSTANCE.Write(writer, value.Status)
	FfiConverterBoolINSTANCE.Write(writer, value.Done)
	FfiConverterSequenceTypeWrappedCloudSyncMessageINSTANCE.Write(writer, value.Messages)
}

type FfiDestroyerTypeWrappedCloudSyncMessagesPage struct{}

func (_ FfiDestroyerTypeWrappedCloudSyncMessagesPage) Destroy(value WrappedCloudSyncMessagesPage) {
	value.Destroy()
}

type WrappedConversation struct {
	Participants []string
	GroupName    *string
	SenderGuid   *string
	IsSms        bool
}

func (r *WrappedConversation) Destroy() {
	FfiDestroyerSequenceString{}.Destroy(r.Participants)
	FfiDestroyerOptionalString{}.Destroy(r.GroupName)
	FfiDestroyerOptionalString{}.Destroy(r.SenderGuid)
	FfiDestroyerBool{}.Destroy(r.IsSms)
}

type FfiConverterTypeWrappedConversation struct{}

var FfiConverterTypeWrappedConversationINSTANCE = FfiConverterTypeWrappedConversation{}

func (c FfiConverterTypeWrappedConversation) Lift(rb RustBufferI) WrappedConversation {
	return LiftFromRustBuffer[WrappedConversation](c, rb)
}

func (c FfiConverterTypeWrappedConversation) Read(reader io.Reader) WrappedConversation {
	return WrappedConversation{
		FfiConverterSequenceStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedConversation) Lower(value WrappedConversation) RustBuffer {
	return LowerIntoRustBuffer[WrappedConversation](c, value)
}

func (c FfiConverterTypeWrappedConversation) Write(writer io.Writer, value WrappedConversation) {
	FfiConverterSequenceStringINSTANCE.Write(writer, value.Participants)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.GroupName)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.SenderGuid)
	FfiConverterBoolINSTANCE.Write(writer, value.IsSms)
}

type FfiDestroyerTypeWrappedConversation struct{}

func (_ FfiDestroyerTypeWrappedConversation) Destroy(value WrappedConversation) {
	value.Destroy()
}

type WrappedMessage struct {
	Uuid                  string
	Sender                *string
	Text                  *string
	Subject               *string
	Participants          []string
	GroupName             *string
	TimestampMs           uint64
	IsSms                 bool
	IsTapback             bool
	TapbackType           *uint32
	TapbackTargetUuid     *string
	TapbackTargetPart     *uint64
	TapbackEmoji          *string
	TapbackRemove         bool
	IsEdit                bool
	EditTargetUuid        *string
	EditPart              *uint64
	EditNewText           *string
	IsUnsend              bool
	UnsendTargetUuid      *string
	UnsendEditPart        *uint64
	IsRename              bool
	NewChatName           *string
	IsParticipantChange   bool
	NewParticipants       []string
	Attachments           []WrappedAttachment
	ReplyGuid             *string
	ReplyPart             *string
	IsTyping              bool
	IsReadReceipt         bool
	IsDelivered           bool
	IsError               bool
	ErrorForUuid          *string
	ErrorStatus           *uint64
	ErrorStatusStr        *string
	IsPeerCacheInvalidate bool
	SendDelivered         bool
	SenderGuid            *string
}

func (r *WrappedMessage) Destroy() {
	FfiDestroyerString{}.Destroy(r.Uuid)
	FfiDestroyerOptionalString{}.Destroy(r.Sender)
	FfiDestroyerOptionalString{}.Destroy(r.Text)
	FfiDestroyerOptionalString{}.Destroy(r.Subject)
	FfiDestroyerSequenceString{}.Destroy(r.Participants)
	FfiDestroyerOptionalString{}.Destroy(r.GroupName)
	FfiDestroyerUint64{}.Destroy(r.TimestampMs)
	FfiDestroyerBool{}.Destroy(r.IsSms)
	FfiDestroyerBool{}.Destroy(r.IsTapback)
	FfiDestroyerOptionalUint32{}.Destroy(r.TapbackType)
	FfiDestroyerOptionalString{}.Destroy(r.TapbackTargetUuid)
	FfiDestroyerOptionalUint64{}.Destroy(r.TapbackTargetPart)
	FfiDestroyerOptionalString{}.Destroy(r.TapbackEmoji)
	FfiDestroyerBool{}.Destroy(r.TapbackRemove)
	FfiDestroyerBool{}.Destroy(r.IsEdit)
	FfiDestroyerOptionalString{}.Destroy(r.EditTargetUuid)
	FfiDestroyerOptionalUint64{}.Destroy(r.EditPart)
	FfiDestroyerOptionalString{}.Destroy(r.EditNewText)
	FfiDestroyerBool{}.Destroy(r.IsUnsend)
	FfiDestroyerOptionalString{}.Destroy(r.UnsendTargetUuid)
	FfiDestroyerOptionalUint64{}.Destroy(r.UnsendEditPart)
	FfiDestroyerBool{}.Destroy(r.IsRename)
	FfiDestroyerOptionalString{}.Destroy(r.NewChatName)
	FfiDestroyerBool{}.Destroy(r.IsParticipantChange)
	FfiDestroyerSequenceString{}.Destroy(r.NewParticipants)
	FfiDestroyerSequenceTypeWrappedAttachment{}.Destroy(r.Attachments)
	FfiDestroyerOptionalString{}.Destroy(r.ReplyGuid)
	FfiDestroyerOptionalString{}.Destroy(r.ReplyPart)
	FfiDestroyerBool{}.Destroy(r.IsTyping)
	FfiDestroyerBool{}.Destroy(r.IsReadReceipt)
	FfiDestroyerBool{}.Destroy(r.IsDelivered)
	FfiDestroyerBool{}.Destroy(r.IsError)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorForUuid)
	FfiDestroyerOptionalUint64{}.Destroy(r.ErrorStatus)
	FfiDestroyerOptionalString{}.Destroy(r.ErrorStatusStr)
	FfiDestroyerBool{}.Destroy(r.IsPeerCacheInvalidate)
	FfiDestroyerBool{}.Destroy(r.SendDelivered)
	FfiDestroyerOptionalString{}.Destroy(r.SenderGuid)
}

type FfiConverterTypeWrappedMessage struct{}

var FfiConverterTypeWrappedMessageINSTANCE = FfiConverterTypeWrappedMessage{}

func (c FfiConverterTypeWrappedMessage) Lift(rb RustBufferI) WrappedMessage {
	return LiftFromRustBuffer[WrappedMessage](c, rb)
}

func (c FfiConverterTypeWrappedMessage) Read(reader io.Reader) WrappedMessage {
	return WrappedMessage{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalUint32INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
		FfiConverterSequenceTypeWrappedAttachmentINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeWrappedMessage) Lower(value WrappedMessage) RustBuffer {
	return LowerIntoRustBuffer[WrappedMessage](c, value)
}

func (c FfiConverterTypeWrappedMessage) Write(writer io.Writer, value WrappedMessage) {
	FfiConverterStringINSTANCE.Write(writer, value.Uuid)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Sender)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Text)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Subject)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.Participants)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.GroupName)
	FfiConverterUint64INSTANCE.Write(writer, value.TimestampMs)
	FfiConverterBoolINSTANCE.Write(writer, value.IsSms)
	FfiConverterBoolINSTANCE.Write(writer, value.IsTapback)
	FfiConverterOptionalUint32INSTANCE.Write(writer, value.TapbackType)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.TapbackTargetUuid)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.TapbackTargetPart)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.TapbackEmoji)
	FfiConverterBoolINSTANCE.Write(writer, value.TapbackRemove)
	FfiConverterBoolINSTANCE.Write(writer, value.IsEdit)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.EditTargetUuid)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.EditPart)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.EditNewText)
	FfiConverterBoolINSTANCE.Write(writer, value.IsUnsend)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.UnsendTargetUuid)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.UnsendEditPart)
	FfiConverterBoolINSTANCE.Write(writer, value.IsRename)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.NewChatName)
	FfiConverterBoolINSTANCE.Write(writer, value.IsParticipantChange)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.NewParticipants)
	FfiConverterSequenceTypeWrappedAttachmentINSTANCE.Write(writer, value.Attachments)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ReplyGuid)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ReplyPart)
	FfiConverterBoolINSTANCE.Write(writer, value.IsTyping)
	FfiConverterBoolINSTANCE.Write(writer, value.IsReadReceipt)
	FfiConverterBoolINSTANCE.Write(writer, value.IsDelivered)
	FfiConverterBoolINSTANCE.Write(writer, value.IsError)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorForUuid)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.ErrorStatus)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ErrorStatusStr)
	FfiConverterBoolINSTANCE.Write(writer, value.IsPeerCacheInvalidate)
	FfiConverterBoolINSTANCE.Write(writer, value.SendDelivered)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.SenderGuid)
}

type FfiDestroyerTypeWrappedMessage struct{}

func (_ FfiDestroyerTypeWrappedMessage) Destroy(value WrappedMessage) {
	value.Destroy()
}

type WrappedError struct {
	err error
}

func (err WrappedError) Error() string {
	return fmt.Sprintf("WrappedError: %s", err.err.Error())
}

func (err WrappedError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrWrappedErrorGenericError = fmt.Errorf("WrappedErrorGenericError")

// Variant structs
type WrappedErrorGenericError struct {
	Msg string
}

func NewWrappedErrorGenericError(
	msg string,
) *WrappedError {
	return &WrappedError{
		err: &WrappedErrorGenericError{
			Msg: msg,
		},
	}
}

func (err WrappedErrorGenericError) Error() string {
	return fmt.Sprint("GenericError",
		": ",

		"Msg=",
		err.Msg,
	)
}

func (self WrappedErrorGenericError) Is(target error) bool {
	return target == ErrWrappedErrorGenericError
}

type FfiConverterTypeWrappedError struct{}

var FfiConverterTypeWrappedErrorINSTANCE = FfiConverterTypeWrappedError{}

func (c FfiConverterTypeWrappedError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeWrappedError) Lower(value *WrappedError) RustBuffer {
	return LowerIntoRustBuffer[*WrappedError](c, value)
}

func (c FfiConverterTypeWrappedError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &WrappedError{&WrappedErrorGenericError{
			Msg: FfiConverterStringINSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeWrappedError.Read()", errorID))
	}
}

func (c FfiConverterTypeWrappedError) Write(writer io.Writer, value *WrappedError) {
	switch variantValue := value.err.(type) {
	case *WrappedErrorGenericError:
		writeInt32(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Msg)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeWrappedError.Write", value))
	}
}

type uniffiCallbackResult C.int32_t

const (
	uniffiIdxCallbackFree               uniffiCallbackResult = 0
	uniffiCallbackResultSuccess         uniffiCallbackResult = 0
	uniffiCallbackResultError           uniffiCallbackResult = 1
	uniffiCallbackUnexpectedResultError uniffiCallbackResult = 2
	uniffiCallbackCancelled             uniffiCallbackResult = 3
)

type concurrentHandleMap[T any] struct {
	leftMap       map[uint64]*T
	rightMap      map[*T]uint64
	currentHandle uint64
	lock          sync.RWMutex
}

func newConcurrentHandleMap[T any]() *concurrentHandleMap[T] {
	return &concurrentHandleMap[T]{
		leftMap:  map[uint64]*T{},
		rightMap: map[*T]uint64{},
	}
}

func (cm *concurrentHandleMap[T]) insert(obj *T) uint64 {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if existingHandle, ok := cm.rightMap[obj]; ok {
		return existingHandle
	}
	cm.currentHandle = cm.currentHandle + 1
	cm.leftMap[cm.currentHandle] = obj
	cm.rightMap[obj] = cm.currentHandle
	return cm.currentHandle
}

func (cm *concurrentHandleMap[T]) remove(handle uint64) bool {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if val, ok := cm.leftMap[handle]; ok {
		delete(cm.leftMap, handle)
		delete(cm.rightMap, val)
	}
	return false
}

func (cm *concurrentHandleMap[T]) tryGet(handle uint64) (*T, bool) {
	cm.lock.RLock()
	defer cm.lock.RUnlock()

	val, ok := cm.leftMap[handle]
	return val, ok
}

type FfiConverterCallbackInterface[CallbackInterface any] struct {
	handleMap *concurrentHandleMap[CallbackInterface]
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) drop(handle uint64) RustBuffer {
	c.handleMap.remove(handle)
	return RustBuffer{}
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Lift(handle uint64) CallbackInterface {
	val, ok := c.handleMap.tryGet(handle)
	if !ok {
		panic(fmt.Errorf("no callback in handle map: %d", handle))
	}
	return *val
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Read(reader io.Reader) CallbackInterface {
	return c.Lift(readUint64(reader))
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Lower(value CallbackInterface) C.uint64_t {
	return C.uint64_t(c.handleMap.insert(&value))
}

func (c *FfiConverterCallbackInterface[CallbackInterface]) Write(writer io.Writer, value CallbackInterface) {
	writeUint64(writer, uint64(c.Lower(value)))
}

type MessageCallback interface {
	OnMessage(msg WrappedMessage)
}

// foreignCallbackCallbackInterfaceMessageCallback cannot be callable be a compiled function at a same time
type foreignCallbackCallbackInterfaceMessageCallback struct{}

//export rustpushgo_cgo_MessageCallback
func rustpushgo_cgo_MessageCallback(handle C.uint64_t, method C.int32_t, argsPtr *C.uint8_t, argsLen C.int32_t, outBuf *C.RustBuffer) C.int32_t {
	cb := FfiConverterCallbackInterfaceMessageCallbackINSTANCE.Lift(uint64(handle))
	switch method {
	case 0:
		// 0 means Rust is done with the callback, and the callback
		// can be dropped by the foreign language.
		*outBuf = rustBufferToC(FfiConverterCallbackInterfaceMessageCallbackINSTANCE.drop(uint64(handle)))
		// See docs of ForeignCallback in `uniffi/src/ffi/foreigncallbacks.rs`
		return C.int32_t(uniffiIdxCallbackFree)

	case 1:
		var result uniffiCallbackResult
		args := unsafe.Slice((*byte)(argsPtr), argsLen)
		result = foreignCallbackCallbackInterfaceMessageCallback{}.InvokeOnMessage(cb, args, outBuf)
		return C.int32_t(result)

	default:
		// This should never happen, because an out of bounds method index won't
		// ever be used. Once we can catch errors, we should return an InternalException.
		// https://github.com/mozilla/uniffi-rs/issues/351
		return C.int32_t(uniffiCallbackUnexpectedResultError)
	}
}

func (foreignCallbackCallbackInterfaceMessageCallback) InvokeOnMessage(callback MessageCallback, args []byte, outBuf *C.RustBuffer) uniffiCallbackResult {
	reader := bytes.NewReader(args)
	callback.OnMessage(FfiConverterTypeWrappedMessageINSTANCE.Read(reader))

	return uniffiCallbackResultSuccess
}

type FfiConverterCallbackInterfaceMessageCallback struct {
	FfiConverterCallbackInterface[MessageCallback]
}

var FfiConverterCallbackInterfaceMessageCallbackINSTANCE = &FfiConverterCallbackInterfaceMessageCallback{
	FfiConverterCallbackInterface: FfiConverterCallbackInterface[MessageCallback]{
		handleMap: newConcurrentHandleMap[MessageCallback](),
	},
}

// This is a static function because only 1 instance is supported for registering
func (c *FfiConverterCallbackInterfaceMessageCallback) register() {
	rustCall(func(status *C.RustCallStatus) int32 {
		C.uniffi_rustpushgo_fn_init_callback_messagecallback(C.ForeignCallback(C.rustpushgo_cgo_MessageCallback), status)
		return 0
	})
}

type FfiDestroyerCallbackInterfaceMessageCallback struct{}

func (FfiDestroyerCallbackInterfaceMessageCallback) Destroy(value MessageCallback) {
}

type UpdateUsersCallback interface {
	UpdateUsers(users *WrappedIdsUsers)
}

// foreignCallbackCallbackInterfaceUpdateUsersCallback cannot be callable be a compiled function at a same time
type foreignCallbackCallbackInterfaceUpdateUsersCallback struct{}

//export rustpushgo_cgo_UpdateUsersCallback
func rustpushgo_cgo_UpdateUsersCallback(handle C.uint64_t, method C.int32_t, argsPtr *C.uint8_t, argsLen C.int32_t, outBuf *C.RustBuffer) C.int32_t {
	cb := FfiConverterCallbackInterfaceUpdateUsersCallbackINSTANCE.Lift(uint64(handle))
	switch method {
	case 0:
		// 0 means Rust is done with the callback, and the callback
		// can be dropped by the foreign language.
		*outBuf = rustBufferToC(FfiConverterCallbackInterfaceUpdateUsersCallbackINSTANCE.drop(uint64(handle)))
		// See docs of ForeignCallback in `uniffi/src/ffi/foreigncallbacks.rs`
		return C.int32_t(uniffiIdxCallbackFree)

	case 1:
		var result uniffiCallbackResult
		args := unsafe.Slice((*byte)(argsPtr), argsLen)
		result = foreignCallbackCallbackInterfaceUpdateUsersCallback{}.InvokeUpdateUsers(cb, args, outBuf)
		return C.int32_t(result)

	default:
		// This should never happen, because an out of bounds method index won't
		// ever be used. Once we can catch errors, we should return an InternalException.
		// https://github.com/mozilla/uniffi-rs/issues/351
		return C.int32_t(uniffiCallbackUnexpectedResultError)
	}
}

func (foreignCallbackCallbackInterfaceUpdateUsersCallback) InvokeUpdateUsers(callback UpdateUsersCallback, args []byte, outBuf *C.RustBuffer) uniffiCallbackResult {
	reader := bytes.NewReader(args)
	callback.UpdateUsers(FfiConverterWrappedIDSUsersINSTANCE.Read(reader))

	return uniffiCallbackResultSuccess
}

type FfiConverterCallbackInterfaceUpdateUsersCallback struct {
	FfiConverterCallbackInterface[UpdateUsersCallback]
}

var FfiConverterCallbackInterfaceUpdateUsersCallbackINSTANCE = &FfiConverterCallbackInterfaceUpdateUsersCallback{
	FfiConverterCallbackInterface: FfiConverterCallbackInterface[UpdateUsersCallback]{
		handleMap: newConcurrentHandleMap[UpdateUsersCallback](),
	},
}

// This is a static function because only 1 instance is supported for registering
func (c *FfiConverterCallbackInterfaceUpdateUsersCallback) register() {
	rustCall(func(status *C.RustCallStatus) int32 {
		C.uniffi_rustpushgo_fn_init_callback_updateuserscallback(C.ForeignCallback(C.rustpushgo_cgo_UpdateUsersCallback), status)
		return 0
	})
}

type FfiDestroyerCallbackInterfaceUpdateUsersCallback struct{}

func (FfiDestroyerCallbackInterfaceUpdateUsersCallback) Destroy(value UpdateUsersCallback) {
}

type FfiConverterOptionalUint32 struct{}

var FfiConverterOptionalUint32INSTANCE = FfiConverterOptionalUint32{}

func (c FfiConverterOptionalUint32) Lift(rb RustBufferI) *uint32 {
	return LiftFromRustBuffer[*uint32](c, rb)
}

func (_ FfiConverterOptionalUint32) Read(reader io.Reader) *uint32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint32INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint32) Lower(value *uint32) RustBuffer {
	return LowerIntoRustBuffer[*uint32](c, value)
}

func (_ FfiConverterOptionalUint32) Write(writer io.Writer, value *uint32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint32INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint32 struct{}

func (_ FfiDestroyerOptionalUint32) Destroy(value *uint32) {
	if value != nil {
		FfiDestroyerUint32{}.Destroy(*value)
	}
}

type FfiConverterOptionalUint64 struct{}

var FfiConverterOptionalUint64INSTANCE = FfiConverterOptionalUint64{}

func (c FfiConverterOptionalUint64) Lift(rb RustBufferI) *uint64 {
	return LiftFromRustBuffer[*uint64](c, rb)
}

func (_ FfiConverterOptionalUint64) Read(reader io.Reader) *uint64 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint64INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint64) Lower(value *uint64) RustBuffer {
	return LowerIntoRustBuffer[*uint64](c, value)
}

func (_ FfiConverterOptionalUint64) Write(writer io.Writer, value *uint64) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint64INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint64 struct{}

func (_ FfiDestroyerOptionalUint64) Destroy(value *uint64) {
	if value != nil {
		FfiDestroyerUint64{}.Destroy(*value)
	}
}

type FfiConverterOptionalString struct{}

var FfiConverterOptionalStringINSTANCE = FfiConverterOptionalString{}

func (c FfiConverterOptionalString) Lift(rb RustBufferI) *string {
	return LiftFromRustBuffer[*string](c, rb)
}

func (_ FfiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalString) Lower(value *string) RustBuffer {
	return LowerIntoRustBuffer[*string](c, value)
}

func (_ FfiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalString struct{}

func (_ FfiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		FfiDestroyerString{}.Destroy(*value)
	}
}

type FfiConverterOptionalBytes struct{}

var FfiConverterOptionalBytesINSTANCE = FfiConverterOptionalBytes{}

func (c FfiConverterOptionalBytes) Lift(rb RustBufferI) *[]byte {
	return LiftFromRustBuffer[*[]byte](c, rb)
}

func (_ FfiConverterOptionalBytes) Read(reader io.Reader) *[]byte {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterBytesINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalBytes) Lower(value *[]byte) RustBuffer {
	return LowerIntoRustBuffer[*[]byte](c, value)
}

func (_ FfiConverterOptionalBytes) Write(writer io.Writer, value *[]byte) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterBytesINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalBytes struct{}

func (_ FfiDestroyerOptionalBytes) Destroy(value *[]byte) {
	if value != nil {
		FfiDestroyerBytes{}.Destroy(*value)
	}
}

type FfiConverterOptionalWrappedIDSNGMIdentity struct{}

var FfiConverterOptionalWrappedIDSNGMIdentityINSTANCE = FfiConverterOptionalWrappedIDSNGMIdentity{}

func (c FfiConverterOptionalWrappedIDSNGMIdentity) Lift(rb RustBufferI) **WrappedIdsngmIdentity {
	return LiftFromRustBuffer[**WrappedIdsngmIdentity](c, rb)
}

func (_ FfiConverterOptionalWrappedIDSNGMIdentity) Read(reader io.Reader) **WrappedIdsngmIdentity {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterWrappedIDSNGMIdentityINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalWrappedIDSNGMIdentity) Lower(value **WrappedIdsngmIdentity) RustBuffer {
	return LowerIntoRustBuffer[**WrappedIdsngmIdentity](c, value)
}

func (_ FfiConverterOptionalWrappedIDSNGMIdentity) Write(writer io.Writer, value **WrappedIdsngmIdentity) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterWrappedIDSNGMIdentityINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalWrappedIdsngmIdentity struct{}

func (_ FfiDestroyerOptionalWrappedIdsngmIdentity) Destroy(value **WrappedIdsngmIdentity) {
	if value != nil {
		FfiDestroyerWrappedIdsngmIdentity{}.Destroy(*value)
	}
}

type FfiConverterOptionalWrappedIDSUsers struct{}

var FfiConverterOptionalWrappedIDSUsersINSTANCE = FfiConverterOptionalWrappedIDSUsers{}

func (c FfiConverterOptionalWrappedIDSUsers) Lift(rb RustBufferI) **WrappedIdsUsers {
	return LiftFromRustBuffer[**WrappedIdsUsers](c, rb)
}

func (_ FfiConverterOptionalWrappedIDSUsers) Read(reader io.Reader) **WrappedIdsUsers {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterWrappedIDSUsersINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalWrappedIDSUsers) Lower(value **WrappedIdsUsers) RustBuffer {
	return LowerIntoRustBuffer[**WrappedIdsUsers](c, value)
}

func (_ FfiConverterOptionalWrappedIDSUsers) Write(writer io.Writer, value **WrappedIdsUsers) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterWrappedIDSUsersINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalWrappedIdsUsers struct{}

func (_ FfiDestroyerOptionalWrappedIdsUsers) Destroy(value **WrappedIdsUsers) {
	if value != nil {
		FfiDestroyerWrappedIdsUsers{}.Destroy(*value)
	}
}

type FfiConverterOptionalWrappedTokenProvider struct{}

var FfiConverterOptionalWrappedTokenProviderINSTANCE = FfiConverterOptionalWrappedTokenProvider{}

func (c FfiConverterOptionalWrappedTokenProvider) Lift(rb RustBufferI) **WrappedTokenProvider {
	return LiftFromRustBuffer[**WrappedTokenProvider](c, rb)
}

func (_ FfiConverterOptionalWrappedTokenProvider) Read(reader io.Reader) **WrappedTokenProvider {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterWrappedTokenProviderINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalWrappedTokenProvider) Lower(value **WrappedTokenProvider) RustBuffer {
	return LowerIntoRustBuffer[**WrappedTokenProvider](c, value)
}

func (_ FfiConverterOptionalWrappedTokenProvider) Write(writer io.Writer, value **WrappedTokenProvider) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterWrappedTokenProviderINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalWrappedTokenProvider struct{}

func (_ FfiDestroyerOptionalWrappedTokenProvider) Destroy(value **WrappedTokenProvider) {
	if value != nil {
		FfiDestroyerWrappedTokenProvider{}.Destroy(*value)
	}
}

type FfiConverterOptionalTypeAccountPersistData struct{}

var FfiConverterOptionalTypeAccountPersistDataINSTANCE = FfiConverterOptionalTypeAccountPersistData{}

func (c FfiConverterOptionalTypeAccountPersistData) Lift(rb RustBufferI) *AccountPersistData {
	return LiftFromRustBuffer[*AccountPersistData](c, rb)
}

func (_ FfiConverterOptionalTypeAccountPersistData) Read(reader io.Reader) *AccountPersistData {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTypeAccountPersistDataINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTypeAccountPersistData) Lower(value *AccountPersistData) RustBuffer {
	return LowerIntoRustBuffer[*AccountPersistData](c, value)
}

func (_ FfiConverterOptionalTypeAccountPersistData) Write(writer io.Writer, value *AccountPersistData) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTypeAccountPersistDataINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTypeAccountPersistData struct{}

func (_ FfiDestroyerOptionalTypeAccountPersistData) Destroy(value *AccountPersistData) {
	if value != nil {
		FfiDestroyerTypeAccountPersistData{}.Destroy(*value)
	}
}

type FfiConverterOptionalMapStringString struct{}

var FfiConverterOptionalMapStringStringINSTANCE = FfiConverterOptionalMapStringString{}

func (c FfiConverterOptionalMapStringString) Lift(rb RustBufferI) *map[string]string {
	return LiftFromRustBuffer[*map[string]string](c, rb)
}

func (_ FfiConverterOptionalMapStringString) Read(reader io.Reader) *map[string]string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterMapStringStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalMapStringString) Lower(value *map[string]string) RustBuffer {
	return LowerIntoRustBuffer[*map[string]string](c, value)
}

func (_ FfiConverterOptionalMapStringString) Write(writer io.Writer, value *map[string]string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterMapStringStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalMapStringString struct{}

func (_ FfiDestroyerOptionalMapStringString) Destroy(value *map[string]string) {
	if value != nil {
		FfiDestroyerMapStringString{}.Destroy(*value)
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct{}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeEscrowDeviceInfo struct{}

var FfiConverterSequenceTypeEscrowDeviceInfoINSTANCE = FfiConverterSequenceTypeEscrowDeviceInfo{}

func (c FfiConverterSequenceTypeEscrowDeviceInfo) Lift(rb RustBufferI) []EscrowDeviceInfo {
	return LiftFromRustBuffer[[]EscrowDeviceInfo](c, rb)
}

func (c FfiConverterSequenceTypeEscrowDeviceInfo) Read(reader io.Reader) []EscrowDeviceInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]EscrowDeviceInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeEscrowDeviceInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeEscrowDeviceInfo) Lower(value []EscrowDeviceInfo) RustBuffer {
	return LowerIntoRustBuffer[[]EscrowDeviceInfo](c, value)
}

func (c FfiConverterSequenceTypeEscrowDeviceInfo) Write(writer io.Writer, value []EscrowDeviceInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]EscrowDeviceInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeEscrowDeviceInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeEscrowDeviceInfo struct{}

func (FfiDestroyerSequenceTypeEscrowDeviceInfo) Destroy(sequence []EscrowDeviceInfo) {
	for _, value := range sequence {
		FfiDestroyerTypeEscrowDeviceInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeWrappedAttachment struct{}

var FfiConverterSequenceTypeWrappedAttachmentINSTANCE = FfiConverterSequenceTypeWrappedAttachment{}

func (c FfiConverterSequenceTypeWrappedAttachment) Lift(rb RustBufferI) []WrappedAttachment {
	return LiftFromRustBuffer[[]WrappedAttachment](c, rb)
}

func (c FfiConverterSequenceTypeWrappedAttachment) Read(reader io.Reader) []WrappedAttachment {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]WrappedAttachment, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeWrappedAttachmentINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeWrappedAttachment) Lower(value []WrappedAttachment) RustBuffer {
	return LowerIntoRustBuffer[[]WrappedAttachment](c, value)
}

func (c FfiConverterSequenceTypeWrappedAttachment) Write(writer io.Writer, value []WrappedAttachment) {
	if len(value) > math.MaxInt32 {
		panic("[]WrappedAttachment is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeWrappedAttachmentINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeWrappedAttachment struct{}

func (FfiDestroyerSequenceTypeWrappedAttachment) Destroy(sequence []WrappedAttachment) {
	for _, value := range sequence {
		FfiDestroyerTypeWrappedAttachment{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeWrappedCloudAttachmentInfo struct{}

var FfiConverterSequenceTypeWrappedCloudAttachmentInfoINSTANCE = FfiConverterSequenceTypeWrappedCloudAttachmentInfo{}

func (c FfiConverterSequenceTypeWrappedCloudAttachmentInfo) Lift(rb RustBufferI) []WrappedCloudAttachmentInfo {
	return LiftFromRustBuffer[[]WrappedCloudAttachmentInfo](c, rb)
}

func (c FfiConverterSequenceTypeWrappedCloudAttachmentInfo) Read(reader io.Reader) []WrappedCloudAttachmentInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]WrappedCloudAttachmentInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeWrappedCloudAttachmentInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeWrappedCloudAttachmentInfo) Lower(value []WrappedCloudAttachmentInfo) RustBuffer {
	return LowerIntoRustBuffer[[]WrappedCloudAttachmentInfo](c, value)
}

func (c FfiConverterSequenceTypeWrappedCloudAttachmentInfo) Write(writer io.Writer, value []WrappedCloudAttachmentInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]WrappedCloudAttachmentInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeWrappedCloudAttachmentInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeWrappedCloudAttachmentInfo struct{}

func (FfiDestroyerSequenceTypeWrappedCloudAttachmentInfo) Destroy(sequence []WrappedCloudAttachmentInfo) {
	for _, value := range sequence {
		FfiDestroyerTypeWrappedCloudAttachmentInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeWrappedCloudSyncChat struct{}

var FfiConverterSequenceTypeWrappedCloudSyncChatINSTANCE = FfiConverterSequenceTypeWrappedCloudSyncChat{}

func (c FfiConverterSequenceTypeWrappedCloudSyncChat) Lift(rb RustBufferI) []WrappedCloudSyncChat {
	return LiftFromRustBuffer[[]WrappedCloudSyncChat](c, rb)
}

func (c FfiConverterSequenceTypeWrappedCloudSyncChat) Read(reader io.Reader) []WrappedCloudSyncChat {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]WrappedCloudSyncChat, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeWrappedCloudSyncChatINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeWrappedCloudSyncChat) Lower(value []WrappedCloudSyncChat) RustBuffer {
	return LowerIntoRustBuffer[[]WrappedCloudSyncChat](c, value)
}

func (c FfiConverterSequenceTypeWrappedCloudSyncChat) Write(writer io.Writer, value []WrappedCloudSyncChat) {
	if len(value) > math.MaxInt32 {
		panic("[]WrappedCloudSyncChat is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeWrappedCloudSyncChatINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeWrappedCloudSyncChat struct{}

func (FfiDestroyerSequenceTypeWrappedCloudSyncChat) Destroy(sequence []WrappedCloudSyncChat) {
	for _, value := range sequence {
		FfiDestroyerTypeWrappedCloudSyncChat{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeWrappedCloudSyncMessage struct{}

var FfiConverterSequenceTypeWrappedCloudSyncMessageINSTANCE = FfiConverterSequenceTypeWrappedCloudSyncMessage{}

func (c FfiConverterSequenceTypeWrappedCloudSyncMessage) Lift(rb RustBufferI) []WrappedCloudSyncMessage {
	return LiftFromRustBuffer[[]WrappedCloudSyncMessage](c, rb)
}

func (c FfiConverterSequenceTypeWrappedCloudSyncMessage) Read(reader io.Reader) []WrappedCloudSyncMessage {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]WrappedCloudSyncMessage, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeWrappedCloudSyncMessageINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeWrappedCloudSyncMessage) Lower(value []WrappedCloudSyncMessage) RustBuffer {
	return LowerIntoRustBuffer[[]WrappedCloudSyncMessage](c, value)
}

func (c FfiConverterSequenceTypeWrappedCloudSyncMessage) Write(writer io.Writer, value []WrappedCloudSyncMessage) {
	if len(value) > math.MaxInt32 {
		panic("[]WrappedCloudSyncMessage is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeWrappedCloudSyncMessageINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeWrappedCloudSyncMessage struct{}

func (FfiDestroyerSequenceTypeWrappedCloudSyncMessage) Destroy(sequence []WrappedCloudSyncMessage) {
	for _, value := range sequence {
		FfiDestroyerTypeWrappedCloudSyncMessage{}.Destroy(value)
	}
}

type FfiConverterMapStringString struct{}

var FfiConverterMapStringStringINSTANCE = FfiConverterMapStringString{}

func (c FfiConverterMapStringString) Lift(rb RustBufferI) map[string]string {
	return LiftFromRustBuffer[map[string]string](c, rb)
}

func (_ FfiConverterMapStringString) Read(reader io.Reader) map[string]string {
	result := make(map[string]string)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterStringINSTANCE.Read(reader)
		value := FfiConverterStringINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapStringString) Lower(value map[string]string) RustBuffer {
	return LowerIntoRustBuffer[map[string]string](c, value)
}

func (_ FfiConverterMapStringString) Write(writer io.Writer, mapValue map[string]string) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[string]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterStringINSTANCE.Write(writer, key)
		FfiConverterStringINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapStringString struct{}

func (_ FfiDestroyerMapStringString) Destroy(mapValue map[string]string) {
	for key, value := range mapValue {
		FfiDestroyerString{}.Destroy(key)
		FfiDestroyerString{}.Destroy(value)
	}
}

const (
	uniffiRustFuturePollReady      C.int8_t = 0
	uniffiRustFuturePollMaybeReady C.int8_t = 1
)

func uniffiRustCallAsync(
	rustFutureFunc func(*C.RustCallStatus) *C.void,
	pollFunc func(*C.void, unsafe.Pointer, *C.RustCallStatus),
	completeFunc func(*C.void, *C.RustCallStatus),
	_liftFunc func(bool),
	freeFunc func(*C.void, *C.RustCallStatus),
) {
	rustFuture, err := uniffiRustCallAsyncInner(nil, rustFutureFunc, pollFunc, freeFunc)
	if err != nil {
		panic(err)
	}
	defer rustCall(func(status *C.RustCallStatus) int {
		freeFunc(rustFuture, status)
		return 0
	})

	rustCall(func(status *C.RustCallStatus) int {
		completeFunc(rustFuture, status)
		return 0
	})
}

func uniffiRustCallAsyncWithResult[T any, U any](
	rustFutureFunc func(*C.RustCallStatus) *C.void,
	pollFunc func(*C.void, unsafe.Pointer, *C.RustCallStatus),
	completeFunc func(*C.void, *C.RustCallStatus) T,
	liftFunc func(T) U,
	freeFunc func(*C.void, *C.RustCallStatus),
) U {
	rustFuture, err := uniffiRustCallAsyncInner(nil, rustFutureFunc, pollFunc, freeFunc)
	if err != nil {
		panic(err)
	}

	defer rustCall(func(status *C.RustCallStatus) int {
		freeFunc(rustFuture, status)
		return 0
	})

	res := rustCall(func(status *C.RustCallStatus) T {
		return completeFunc(rustFuture, status)
	})
	return liftFunc(res)
}

func uniffiRustCallAsyncWithError(
	converter BufLifter[error],
	rustFutureFunc func(*C.RustCallStatus) *C.void,
	pollFunc func(*C.void, unsafe.Pointer, *C.RustCallStatus),
	completeFunc func(*C.void, *C.RustCallStatus),
	_liftFunc func(bool),
	freeFunc func(*C.void, *C.RustCallStatus),
) error {
	rustFuture, err := uniffiRustCallAsyncInner(converter, rustFutureFunc, pollFunc, freeFunc)
	if err != nil {
		return err
	}

	defer rustCall(func(status *C.RustCallStatus) int {
		freeFunc(rustFuture, status)
		return 0
	})

	_, err = rustCallWithError(converter, func(status *C.RustCallStatus) int {
		completeFunc(rustFuture, status)
		return 0
	})
	return err
}

func uniffiRustCallAsyncWithErrorAndResult[T any, U any](
	converter BufLifter[error],
	rustFutureFunc func(*C.RustCallStatus) *C.void,
	pollFunc func(*C.void, unsafe.Pointer, *C.RustCallStatus),
	completeFunc func(*C.void, *C.RustCallStatus) T,
	liftFunc func(T) U,
	freeFunc func(*C.void, *C.RustCallStatus),
) (U, error) {
	var returnValue U
	rustFuture, err := uniffiRustCallAsyncInner(converter, rustFutureFunc, pollFunc, freeFunc)
	if err != nil {
		return returnValue, err
	}

	defer rustCall(func(status *C.RustCallStatus) int {
		freeFunc(rustFuture, status)
		return 0
	})

	res, err := rustCallWithError(converter, func(status *C.RustCallStatus) T {
		return completeFunc(rustFuture, status)
	})
	if err != nil {
		return returnValue, err
	}
	return liftFunc(res), nil
}

func uniffiRustCallAsyncInner(
	converter BufLifter[error],
	rustFutureFunc func(*C.RustCallStatus) *C.void,
	pollFunc func(*C.void, unsafe.Pointer, *C.RustCallStatus),
	freeFunc func(*C.void, *C.RustCallStatus),
) (*C.void, error) {
	pollResult := C.int8_t(-1)
	waiter := make(chan C.int8_t, 1)
	chanHandle := cgo.NewHandle(waiter)

	rustFuture, err := rustCallWithError(converter, func(status *C.RustCallStatus) *C.void {
		return rustFutureFunc(status)
	})
	if err != nil {
		return nil, err
	}

	defer chanHandle.Delete()

	for pollResult != uniffiRustFuturePollReady {
		ptr := unsafe.Pointer(&chanHandle)
		_, err = rustCallWithError(converter, func(status *C.RustCallStatus) int {
			pollFunc(rustFuture, ptr, status)
			return 0
		})
		if err != nil {
			return nil, err
		}
		res := <-waiter
		pollResult = res
	}

	return rustFuture, nil
}

// Callback handlers for an async calls.  These are invoked by Rust when the future is ready.  They
// lift the return value or error and resume the suspended function.

//export uniffiFutureContinuationCallbackrustpushgo
func uniffiFutureContinuationCallbackrustpushgo(ptr unsafe.Pointer, pollResult C.int8_t) {
	doneHandle := *(*cgo.Handle)(ptr)
	done := doneHandle.Value().((chan C.int8_t))
	done <- pollResult
}

func uniffiInitContinuationCallback() {
	rustCall(func(uniffiStatus *C.RustCallStatus) bool {
		C.ffi_rustpushgo_rust_future_continuation_callback_set(
			C.RustFutureContinuation(C.uniffiFutureContinuationCallbackrustpushgo),
			uniffiStatus,
		)
		return false
	})
}

func Connect(config *WrappedOsConfig, state *WrappedApsState) *WrappedApsConnection {
	return uniffiRustCallAsyncWithResult(func(status *C.RustCallStatus) *C.void {
		// rustFutureFunc
		return (*C.void)(C.uniffi_rustpushgo_fn_func_connect(FfiConverterWrappedOSConfigINSTANCE.Lower(config), FfiConverterWrappedAPSStateINSTANCE.Lower(state),
			status,
		))
	},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_pointer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) unsafe.Pointer {
			// completeFunc
			return C.ffi_rustpushgo_rust_future_complete_pointer(unsafe.Pointer(handle), status)
		},
		FfiConverterWrappedAPSConnectionINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_pointer(unsafe.Pointer(rustFuture), status)
		})
}

func CreateConfigFromHardwareKey(base64Key string) (*WrappedOsConfig, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeWrappedError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_func_create_config_from_hardware_key(rustBufferToC(FfiConverterStringINSTANCE.Lower(base64Key)), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *WrappedOsConfig
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterWrappedOSConfigINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func CreateConfigFromHardwareKeyWithDeviceId(base64Key string, deviceId string) (*WrappedOsConfig, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeWrappedError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_func_create_config_from_hardware_key_with_device_id(rustBufferToC(FfiConverterStringINSTANCE.Lower(base64Key)), rustBufferToC(FfiConverterStringINSTANCE.Lower(deviceId)), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *WrappedOsConfig
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterWrappedOSConfigINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func CreateLocalMacosConfig() (*WrappedOsConfig, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeWrappedError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_func_create_local_macos_config(_uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *WrappedOsConfig
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterWrappedOSConfigINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func CreateLocalMacosConfigWithDeviceId(deviceId string) (*WrappedOsConfig, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeWrappedError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_rustpushgo_fn_func_create_local_macos_config_with_device_id(rustBufferToC(FfiConverterStringINSTANCE.Lower(deviceId)), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *WrappedOsConfig
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterWrappedOSConfigINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func InitLogger() {
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rustpushgo_fn_func_init_logger(_uniffiStatus)
		return false
	})
}

func LoginStart(appleId string, password string, config *WrappedOsConfig, connection *WrappedApsConnection) (*LoginSession, error) {
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_func_login_start(rustBufferToC(FfiConverterStringINSTANCE.Lower(appleId)), rustBufferToC(FfiConverterStringINSTANCE.Lower(password)), FfiConverterWrappedOSConfigINSTANCE.Lower(config), FfiConverterWrappedAPSConnectionINSTANCE.Lower(connection),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_pointer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) unsafe.Pointer {
			// completeFunc
			return C.ffi_rustpushgo_rust_future_complete_pointer(unsafe.Pointer(handle), status)
		},
		FfiConverterLoginSessionINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_pointer(unsafe.Pointer(rustFuture), status)
		})
}

func NewClient(connection *WrappedApsConnection, users *WrappedIdsUsers, identity *WrappedIdsngmIdentity, config *WrappedOsConfig, tokenProvider **WrappedTokenProvider, messageCallback MessageCallback, updateUsersCallback UpdateUsersCallback) (*Client, error) {
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_func_new_client(FfiConverterWrappedAPSConnectionINSTANCE.Lower(connection), FfiConverterWrappedIDSUsersINSTANCE.Lower(users), FfiConverterWrappedIDSNGMIdentityINSTANCE.Lower(identity), FfiConverterWrappedOSConfigINSTANCE.Lower(config), rustBufferToC(FfiConverterOptionalWrappedTokenProviderINSTANCE.Lower(tokenProvider)), FfiConverterCallbackInterfaceMessageCallbackINSTANCE.Lower(messageCallback), FfiConverterCallbackInterfaceUpdateUsersCallbackINSTANCE.Lower(updateUsersCallback),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_pointer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) unsafe.Pointer {
			// completeFunc
			return C.ffi_rustpushgo_rust_future_complete_pointer(unsafe.Pointer(handle), status)
		},
		FfiConverterClientINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_pointer(unsafe.Pointer(rustFuture), status)
		})
}

func RestoreTokenProvider(config *WrappedOsConfig, connection *WrappedApsConnection, username string, hashedPasswordHex string, pet string, spdBase64 string) (*WrappedTokenProvider, error) {
	return uniffiRustCallAsyncWithErrorAndResult(
		FfiConverterTypeWrappedError{}, func(status *C.RustCallStatus) *C.void {
			// rustFutureFunc
			return (*C.void)(C.uniffi_rustpushgo_fn_func_restore_token_provider(FfiConverterWrappedOSConfigINSTANCE.Lower(config), FfiConverterWrappedAPSConnectionINSTANCE.Lower(connection), rustBufferToC(FfiConverterStringINSTANCE.Lower(username)), rustBufferToC(FfiConverterStringINSTANCE.Lower(hashedPasswordHex)), rustBufferToC(FfiConverterStringINSTANCE.Lower(pet)), rustBufferToC(FfiConverterStringINSTANCE.Lower(spdBase64)),
				status,
			))
		},
		func(handle *C.void, ptr unsafe.Pointer, status *C.RustCallStatus) {
			// pollFunc
			C.ffi_rustpushgo_rust_future_poll_pointer(unsafe.Pointer(handle), ptr, status)
		},
		func(handle *C.void, status *C.RustCallStatus) unsafe.Pointer {
			// completeFunc
			return C.ffi_rustpushgo_rust_future_complete_pointer(unsafe.Pointer(handle), status)
		},
		FfiConverterWrappedTokenProviderINSTANCE.Lift, func(rustFuture *C.void, status *C.RustCallStatus) {
			// freeFunc
			C.ffi_rustpushgo_rust_future_free_pointer(unsafe.Pointer(rustFuture), status)
		})
}
