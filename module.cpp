#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "config.h"
#include "base64.hpp"
#include "gzip.hpp"

#include <iostream>
#include <cstdint>
#include <string>
#include <gmlib/rng/std_rng.h>
#include <gmlib/sm2/sm2.h>
#include <gmlib/sm3/sm3.h>
#include <gmlib/sm4/sm4.h>
#include <gmlib/sm4/sm4_mode.h>

using namespace Pectics;

constexpr size_t BUFFER_SIZE = 16384;

// const std::string BASE64_PRIVATE_KEY = "P3s0+rMuY4Nt5cUWuOCjMhDzVNdom+W0RvdV6ngM+/E=";
constexpr uint8_t PRIVATE_KEY[32] = {
	0x3f, 0x7b, 0x34, 0xfa, 0xb3, 0x2e, 0x63, 0x83,
	0x6d, 0xe5, 0xc5, 0x16, 0xb8, 0xe0, 0xa3, 0x32,
	0x10, 0xf3, 0x54, 0xd7, 0x68, 0x9b, 0xe5, 0xb4,
	0x46, 0xf7, 0x55, 0xea, 0x78, 0x0c, 0xfb, 0xf1,
};

//const std::string BASE64_PUBLIC_KEY = "BL7JvEAV7Wci0h5YAysN0BPNVdcUhuyJszJLRwnurav0CGftcrVcvrWeCPBIjIIBF371teRbrCS9V1Wyq7i3Arc=";
// REMEMBER to decode and remove the point(.) at the first character!!!!!!!!!!
constexpr uint8_t PUBLIC_KEY[2][32] = { {
	0xbe, 0xc9, 0xbc, 0x40, 0x15, 0xed, 0x67, 0x22,
	0xd2, 0x1e, 0x58, 0x03, 0x2b, 0x0d, 0xd0, 0x13,
	0xcd, 0x55, 0xd7, 0x14, 0x86, 0xec, 0x89, 0xb3,
	0x32, 0x4b, 0x47, 0x09, 0xee, 0xad, 0xab, 0xf4,
}, {
	0x08, 0x67, 0xed, 0x72, 0xb5, 0x5c, 0xbe, 0xb5,
	0x9e, 0x08, 0xf0, 0x48, 0x8c, 0x82, 0x01, 0x17,
	0x7e, 0xf5, 0xb5, 0xe4, 0x5b, 0xac, 0x24, 0xbd,
	0x57, 0x55, 0xb2, 0xab, 0xb8, 0xb7, 0x02, 0xb7,
} };

static PyObject* C_SM2Encrypt(PyObject*, PyObject* o) {

	// check input
	if (!PyUnicode_Check(o)) {
		PyErr_SetString(PyExc_UnicodeError, "Input is not a string");
		return _Py_NULL;
	}

	// parse text
	std::string text = PyBytes_AsString(PyUnicode_AsUTF8String(o));
	size_t len = text.size();
	std::vector<uint8_t> plain(len);
	std::copy(text.begin(), text.end(), plain.begin());

	// init pub_key
	sm2::SM2PublicKey<sm3::SM3> pub_key(PUBLIC_KEY[0], PUBLIC_KEY[1]);

	// error: buffer overflow
	if (pub_key.ciphertext_len(plain.data(), len) > BUFFER_SIZE) {
		PyErr_SetString(PyExc_BufferError, "Buffer overflow");
		return _Py_NULL;
	}

	// encrypt
	std::vector<uint8_t> cipher(BUFFER_SIZE);
	size_t cipher_len;
	rng::StdRng rng;
	pub_key.encrypt(cipher.data(), &cipher_len, plain.data(), len, rng);
	std::string ret = Base64::EncodeAsString(cipher.data(), cipher_len);

	// return
	return PyUnicode_FromStringAndSize(ret.c_str(), ret.size());
}

static PyObject* C_SM2Decrypt(PyObject*, PyObject* o) {

	// Check input
	if (!PyUnicode_Check(o)) {
		PyErr_SetString(PyExc_UnicodeError, "Input is not a string");
		return _Py_NULL;
	}

	// Parse cipher text
	std::string text = PyBytes_AsString(PyUnicode_AsUTF8String(o));
	size_t len = (text.size() / 4) * 3;
	if (text.size() >= 1 && text[text.size() - 1] == '=') len--;
	if (text.size() >= 2 && text[text.size() - 2] == '=') len--;

	std::vector<uint8_t> cipher(len);
	Base64::Decode(reinterpret_cast<const uint8_t*>(text.c_str()), text.size(), cipher.data());

	// Initialize private key
	sm2::SM2PrivateKey<sm3::SM3> pri_key(PRIVATE_KEY);

	// Check buffer size
	size_t expected_len = pri_key.plaintext_len(cipher.data(), len);
	if (expected_len > BUFFER_SIZE) {
		PyErr_SetString(PyExc_BufferError, "Buffer overflow");
		return _Py_NULL;
	}

	// Decrypt
	std::vector<uint8_t> plain(BUFFER_SIZE);
	size_t text_len;
	pri_key.decrypt(plain.data(), &text_len, cipher.data(), len);

	// Convert and return
	std::string ret(reinterpret_cast<char*>(plain.data()), text_len);
	return PyUnicode_FromStringAndSize(ret.c_str(), ret.size());
}

static PyObject* C_SM4Encrypt(PyObject*, PyObject* o) {

	// Check input
	if (!PyTuple_Check(o))
		return _Py_NULL;

	// Parse keywords
	const char* t;
	const char* k;
	bool gzip = false;
	if (!PyArg_ParseTuple(o, "ss|i", &t, &k, &gzip))
		return _Py_NULL;

	uint8_t* text = reinterpret_cast<uint8_t*>(const_cast<char*>(t));
	size_t len = strlen(t);
	uint8_t* key_str = reinterpret_cast<uint8_t*>(const_cast<char*>(k));
	size_t key_len = strlen(k);

	// Parse key
	uint8_t key[sm4::SM4::USER_KEY_LEN];
	Base64::Decode(key_str, key_len, key);

	// Initialize encryptor
	sm4::SM4EcbEncryptor enc(key);

	// gzip compress
	if (gzip)
		GZip::Compress(text, len, text, len);

	// Parse text and apply PKCS7 padding
	size_t block_size = sm4::SM4::BLOCK_SIZE;
	size_t padded_len = block_size * (len / block_size + 1);
	std::vector<uint8_t> plain(padded_len, 0);
	std::copy(text, text + len, plain.begin());
	std::fill(plain.begin() + len, plain.end(), padded_len - len);

	// Encrypt
	std::vector<uint8_t> cipher(BUFFER_SIZE);
	size_t cipher_len;
	enc.do_final(cipher.data(), &cipher_len, plain.data(), padded_len);

	// Encode to Base64
	std::string ret = Base64::EncodeAsString(cipher.data(), cipher_len);

	// Return
	return PyUnicode_FromStringAndSize(ret.c_str(), ret.size());
}

static PyObject* C_SM4Decrypt(PyObject*, PyObject* o) {

	// check input
	if (!PyTuple_Check(o))
		return _Py_NULL;

	// parse keywords
	const char* t;
	const char* k;
	bool gzip = false;
	if (!PyArg_ParseTuple(o, "ss|i", &t, &k, &gzip))
		return _Py_NULL;

	uint8_t* text = reinterpret_cast<uint8_t*>(const_cast<char*>(t));
	size_t len = strlen(t);
	uint8_t* key_str = reinterpret_cast<uint8_t*>(const_cast<char*>(k));
	size_t key_len = strlen(k);

	// parse key
	uint8_t key[sm4::SM4::USER_KEY_LEN];
	Base64::Decode(key_str, key_len, key);

	// init dec
	sm4::SM4EcbDecryptor dec(key);

	// parse cipher length and decode
	size_t cipher_len = len / 4 * 3;
	if (len >= 1 && text[len - 1] == '=') cipher_len--;
	if (len >= 2 && text[len - 2] == '=') cipher_len--;
	cipher_len = sm4::SM4::BLOCK_SIZE * (cipher_len / sm4::SM4::BLOCK_SIZE + 1);

	std::vector<uint8_t> cipher(cipher_len);
	Base64::Decode(text, len, cipher.data());

	// decrypt
	std::vector<uint8_t> plain(BUFFER_SIZE);
	size_t plain_len;
	dec.do_final(plain.data(), &plain_len, cipher.data(), cipher_len);

	// gzip decompress
	if (gzip)
		GZip::Decompress(plain.data(), plain_len, plain.data(), plain_len);

	std::string ret(reinterpret_cast<char*>(plain.data()), plain_len);

	// return
	return PyUnicode_FromStringAndSize(ret.c_str(), ret.size());
}

static PyMethodDef methods[] = {
	{ "SM2Encrypt", reinterpret_cast<PyCFunction>(C_SM2Encrypt), METH_O, "Encrypt text with SM2" },
	{ "SM2Decrypt", reinterpret_cast<PyCFunction>(C_SM2Decrypt), METH_O, "Decrypt text with SM2" },
	{ "SM4Encrypt", reinterpret_cast<PyCFunction>(C_SM4Encrypt), METH_VARARGS, "Encrypt text with SM4" },
	{ "SM4Decrypt", reinterpret_cast<PyCFunction>(C_SM4Decrypt), METH_VARARGS, "Decrypt text with SM4" },
	{ nullptr, nullptr, 0, nullptr },
};

static PyModuleDef module = {
	PyModuleDef_HEAD_INIT,
	"CryptUtils",
	"SM2/SM4 encryption and decryption for YUN",
	0,
	methods,
};

PyMODINIT_FUNC PyInit_CryptUtils(void) {
	return PyModule_Create(&module);
}
