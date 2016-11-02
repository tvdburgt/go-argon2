package argon2

// #cgo CFLAGS: -I/usr/include
// #include <argon2.h>
import "C"

import (
	"errors"
	"fmt"
)

// Error represents the internal error code propagated from libargon2.
type Error int

func (e Error) Error() string {
	msg := C.argon2_error_message(C.int(e))
	return fmt.Sprintf("argon2: %s", C.GoString(msg))
}

var (
	ErrContext  = errors.New("argon2: context is nil")
	ErrPassword = errors.New("argon2: password is nil or empty")
	ErrSalt     = errors.New("argon2: salt is nil or empty")
	ErrHash     = errors.New("argon2: hash is nil or empty")
)

var (
	ErrOutputPtrNull         Error = C.ARGON2_OUTPUT_PTR_NULL
	ErrOutputTooShort        Error = C.ARGON2_OUTPUT_TOO_SHORT
	ErrOutputTooLong         Error = C.ARGON2_OUTPUT_TOO_LONG
	ErrPwdTooShort           Error = C.ARGON2_PWD_TOO_SHORT
	ErrPwdTooLong            Error = C.ARGON2_PWD_TOO_LONG
	ErrSaltTooShort          Error = C.ARGON2_SALT_TOO_SHORT
	ErrSaltTooLong           Error = C.ARGON2_SALT_TOO_LONG
	ErrAdTooShort            Error = C.ARGON2_AD_TOO_SHORT
	ErrAdTooLong             Error = C.ARGON2_AD_TOO_LONG
	ErrSecretTooShort        Error = C.ARGON2_SECRET_TOO_SHORT
	ErrSecretTooLong         Error = C.ARGON2_SECRET_TOO_LONG
	ErrTimeTooSmall          Error = C.ARGON2_TIME_TOO_SMALL
	ErrTimeTooLarge          Error = C.ARGON2_TIME_TOO_LARGE
	ErrMemoryTooLittle       Error = C.ARGON2_MEMORY_TOO_LITTLE
	ErrMemoryTooMuch         Error = C.ARGON2_MEMORY_TOO_MUCH
	ErrLanesTooFew           Error = C.ARGON2_LANES_TOO_FEW
	ErrLanesTooMany          Error = C.ARGON2_LANES_TOO_MANY
	ErrPwdPtrMismatch        Error = C.ARGON2_PWD_PTR_MISMATCH
	ErrSaltPtrMismatch       Error = C.ARGON2_SALT_PTR_MISMATCH
	ErrSecretPtrMismatch     Error = C.ARGON2_SECRET_PTR_MISMATCH
	ErrAdPtrMismatch         Error = C.ARGON2_AD_PTR_MISMATCH
	ErrMemoryAllocationError Error = C.ARGON2_MEMORY_ALLOCATION_ERROR
	ErrFreeMemoryCbkNull     Error = C.ARGON2_FREE_MEMORY_CBK_NULL
	ErrAllocateMemoryCbkNull Error = C.ARGON2_ALLOCATE_MEMORY_CBK_NULL
	ErrIncorrectParameter    Error = C.ARGON2_INCORRECT_PARAMETER
	ErrIncorrectType         Error = C.ARGON2_INCORRECT_TYPE
	ErrOutPtrMismatch        Error = C.ARGON2_OUT_PTR_MISMATCH
	ErrThreadsTooFew         Error = C.ARGON2_THREADS_TOO_FEW
	ErrThreadsTooMany        Error = C.ARGON2_THREADS_TOO_MANY
	ErrMissingArgs           Error = C.ARGON2_MISSING_ARGS
	ErrEncodingFail          Error = C.ARGON2_ENCODING_FAIL
	ErrDecodingFail          Error = C.ARGON2_DECODING_FAIL
	ErrThreadFail            Error = C.ARGON2_THREAD_FAIL
	ErrDecodingLengthFail    Error = C.ARGON2_DECODING_LENGTH_FAIL
	ErrVerifyMismatch        Error = C.ARGON2_VERIFY_MISMATCH
)
