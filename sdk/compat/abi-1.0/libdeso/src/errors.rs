// libdeso::errors – Error texts and names.

#[allow(unused_imports)]
use crate::*;

/// Description of an error (a negative syscall result).
pub fn strerror(e: i64) -> &'static str {
    match e {
        ERROR_NOT_PERMITTED => "operation not permitted",
        ERROR_NOT_FOUND => "not found",
        ERROR_NO_PROCESS => "no such process",
        ERROR_INTERRUPTED => "interrupted",
        ERROR_IO => "input / output error",
        ERROR_TOO_MANY_ARGUMENTS => "too many arguments",
        ERROR_NOT_EXECUTABLE => "not an executable (bad ELF file)",
        ERROR_INVALID_HANDLE => "invalid handle",
        ERROR_NO_CHILD => "no child processes",
        ERROR_WOULD_BLOCK => "would have to wait",
        ERROR_OUT_OF_MEMORY => "out of memory",
        ERROR_ACCESS_DENIED => "access denied",
        ERROR_INVALID_ADDRESS => "invalid memory address",
        ERROR_BUSY => "already in use",
        ERROR_ALREADY_EXISTS => "already exists",
        ERROR_NO_DEVICE => "no such device",
        ERROR_NOT_DIRECTORY => "not a directory",
        ERROR_IS_DIRECTORY => "is a directory",
        ERROR_INVALID_ARGUMENT => "invalid argument",
        ERROR_TOO_MANY_HANDLES => "too many handles",
        ERROR_NO_SPACE => "no space left",
        ERROR_NOT_SEEKABLE => "not seekable",
        ERROR_READ_ONLY => "read-only",
        ERROR_CLOSED => "the other end is closed",
        ERROR_BUFFER_TOO_SMALL => "buffer too small",
        ERROR_NOT_IMPLEMENTED => "no such system call",
        ERROR_NOT_EMPTY => "directory not empty",
        ERROR_MESSAGE_TOO_LARGE => "message too large",
        ERROR_TIMED_OUT => "timed out",
        ERROR_ABI => "program needs a newer system ABI",
        _ => "error",
    }
}

/// The name of an error ("ERROR_ACCESS_DENIED"); "ERROR" for an unknown number.
pub fn error_name(e: i64) -> &'static str {
    match e {
        ERROR_NOT_PERMITTED => "ERROR_NOT_PERMITTED",
        ERROR_NOT_FOUND => "ERROR_NOT_FOUND",
        ERROR_NO_PROCESS => "ERROR_NO_PROCESS",
        ERROR_INTERRUPTED => "ERROR_INTERRUPTED",
        ERROR_IO => "ERROR_IO",
        ERROR_TOO_MANY_ARGUMENTS => "ERROR_TOO_MANY_ARGUMENTS",
        ERROR_NOT_EXECUTABLE => "ERROR_NOT_EXECUTABLE",
        ERROR_INVALID_HANDLE => "ERROR_INVALID_HANDLE",
        ERROR_NO_CHILD => "ERROR_NO_CHILD",
        ERROR_WOULD_BLOCK => "ERROR_WOULD_BLOCK",
        ERROR_OUT_OF_MEMORY => "ERROR_OUT_OF_MEMORY",
        ERROR_ACCESS_DENIED => "ERROR_ACCESS_DENIED",
        ERROR_INVALID_ADDRESS => "ERROR_INVALID_ADDRESS",
        ERROR_BUSY => "ERROR_BUSY",
        ERROR_ALREADY_EXISTS => "ERROR_ALREADY_EXISTS",
        ERROR_NO_DEVICE => "ERROR_NO_DEVICE",
        ERROR_NOT_DIRECTORY => "ERROR_NOT_DIRECTORY",
        ERROR_IS_DIRECTORY => "ERROR_IS_DIRECTORY",
        ERROR_INVALID_ARGUMENT => "ERROR_INVALID_ARGUMENT",
        ERROR_TOO_MANY_HANDLES => "ERROR_TOO_MANY_HANDLES",
        ERROR_NO_SPACE => "ERROR_NO_SPACE",
        ERROR_NOT_SEEKABLE => "ERROR_NOT_SEEKABLE",
        ERROR_READ_ONLY => "ERROR_READ_ONLY",
        ERROR_CLOSED => "ERROR_CLOSED",
        ERROR_BUFFER_TOO_SMALL => "ERROR_BUFFER_TOO_SMALL",
        ERROR_NOT_IMPLEMENTED => "ERROR_NOT_IMPLEMENTED",
        ERROR_NOT_EMPTY => "ERROR_NOT_EMPTY",
        ERROR_MESSAGE_TOO_LARGE => "ERROR_MESSAGE_TOO_LARGE",
        ERROR_TIMED_OUT => "ERROR_TIMED_OUT",
        ERROR_ABI => "ERROR_ABI",
        _ => "ERROR",
    }
}
