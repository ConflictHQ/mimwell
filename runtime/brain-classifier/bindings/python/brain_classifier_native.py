"""In-process binding for the operator-selected native classifier, C ABI v1.

This low-level binding is not an intake host. Authorize exact sources/model,
reserve execution, record usage and enforce review in the embedding application.
The installed library and its directory must be trusted and immutable to other
writers. Hash verification is not a sandbox or an atomic installation protocol.
"""
import ctypes
import hashlib
from pathlib import Path
import re


class NativeClassifierError(ValueError):
    pass


class NativeClassifier:
    def __init__(self, library, *, sha256):
        path = Path(library)
        if (not isinstance(sha256, str) or not re.fullmatch('[0-9a-f]{64}', sha256)
                or path != path.resolve() or not path.is_file()):
            raise NativeClassifierError('invalid-library-selection')
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != sha256:
            raise NativeClassifierError('library-pin-changed')
        self.sha256 = sha256
        self._library = ctypes.CDLL(str(path))
        capacity = self._library.brain_classifier_output_capacity_v1
        capacity.argtypes, capacity.restype = [], ctypes.c_size_t
        self._capacity = capacity()
        if self._capacity != 2_097_152:
            raise NativeClassifierError('unsupported-library-capacity')
        self._call = self._library.brain_classifier_classify_v1
        self._call.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                              ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte),
                              ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self._call.restype = ctypes.c_int32

    def classify(self, bundle, *, sha256, request):
        if (not isinstance(request, bytes) or len(request) > 1_048_576
                or not isinstance(sha256, str) or not re.fullmatch('[0-9a-f]{64}', sha256)):
            raise NativeClassifierError('invalid-pin-or-input-budget')
        path = str(bundle).encode('utf-8')
        output = (ctypes.c_ubyte * self._capacity)()
        length = ctypes.c_size_t(0)
        status = self._call(path, len(path), sha256.encode('ascii'), 64,
                            request, len(request), output, self._capacity, ctypes.byref(length))
        if length.value > self._capacity:
            raise NativeClassifierError('invalid-library-response')
        raw = bytes(output[:length.value])
        if status:
            # Never include request bytes, paths, model labels or a foreign error
            # body's arbitrary contents in the exception text.
            raise NativeClassifierError(f'native-classifier-rejected:{status}')
        return raw
