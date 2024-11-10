#pragma once

#include <iostream>
#include <cstdint>
#include <string>
#include <vector>

#define length size_t
#define byte uint8_t
#define bytes std::vector<byte>
#define string std::string

// Modified from macaron/base64.h
namespace Pectics {

    class Base64 {
    private:
        static length LenEncoded(const length& len) {
            return 4 * ((len + 2) / 3);
        }
        static length LenDecoded(const byte* base64, const length& len) {
            length len_decoded = len / 4 * 3;
            if (len >= 1 && base64[len - 1] == '=')
                len_decoded--;
            if (len >= 2 && base64[len - 2] == '=')
                len_decoded--;
            return len_decoded;
        }
    public:
		// Origin Encode
        static void Encode(const byte* in, const length& in_len, byte* out) {
            static constexpr char ENCODING_TABLE[] = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                '4', '5', '6', '7', '8', '9', '+', '/',
            };

			length out_len = LenEncoded(in_len);
            if (out == nullptr)
                out = new byte[out_len];

            length i;
            for (i = 0; in_len > 2 && i < in_len - 2; i += 3) {
                *out++ = ENCODING_TABLE[(in[i] >> 2) & 0x3F];
                *out++ = ENCODING_TABLE[((in[i] & 0x3) << 4) |
                    ((int)(in[i + 1] & 0xF0) >> 4)];
                *out++ = ENCODING_TABLE[((in[i + 1] & 0xF) << 2) |
                    ((int)(in[i + 2] & 0xC0) >> 6)];
                *out++ = ENCODING_TABLE[in[i + 2] & 0x3F];
            }
            if (i < in_len) {
                *out++ = ENCODING_TABLE[(in[i] >> 2) & 0x3F];
                if (i == (in_len - 1)) {
                    *out++ = ENCODING_TABLE[((in[i] & 0x3) << 4)];
                    *out++ = '=';
                }
                else {
                    *out++ = ENCODING_TABLE[((in[i] & 0x3) << 4) |
                        ((int)(in[i + 1] & 0xF0) >> 4)];
                    *out++ = ENCODING_TABLE[((in[i + 1] & 0xF) << 2)];
                }
                *out++ = '=';
            }
        }

        // Origin Decode
        static bool Decode(const byte* in, const length& in_len, byte* out) {
            static constexpr byte DECODING_TABLE[] = {
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
                64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
                64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            };

            if (in_len % 4 != 0)
				return false;

            length out_len = LenDecoded(in, in_len);

            if (out == nullptr)
                out = new byte[out_len];

            for (length i = 0, j = 0; i < in_len;) {
                byte a = in[i] == '='
                    ? 0 & i++
                    : DECODING_TABLE[static_cast<int>(in[i++])];
                byte b = in[i] == '='
                    ? 0 & i++
                    : DECODING_TABLE[static_cast<int>(in[i++])];
                byte c = in[i] == '='
                    ? 0 & i++
                    : DECODING_TABLE[static_cast<int>(in[i++])];
                byte d = in[i] == '='
                    ? 0 & i++
                    : DECODING_TABLE[static_cast<int>(in[i++])];

                uint32_t triple = a << 18 | b << 12 | c << 6 | d;

                if (j < out_len)
                    out[j++] = (triple >> 16) & 0xFF;
                if (j < out_len)
                    out[j++] = (triple >> 8) & 0xFF;
                if (j < out_len)
                    out[j++] = triple & 0xFF;
            }

            return true;
        }

		// Origin EncodeAsString
        static string EncodeAsString(const byte* in, const length& in_len) {
			string out(LenEncoded(in_len), '\0');
			Encode(in, in_len, reinterpret_cast<byte*>(&out[0]));
			return out;
		}

		static string EncodeAsString(const string& in) {
            byte* _in = reinterpret_cast<byte*>(const_cast<char*>(in.c_str()));
			return EncodeAsString(_in, in.size());
		}

		static string EncodeAsString(const bytes& in) {
			return EncodeAsString(in.data(), in.size());
		}

		// Origin EncodeAsVector
		static bytes EncodeAsVector(const byte* in, const length& in_len) {
            length out_len = LenEncoded(in_len);
			byte* _out = new byte[out_len];
			Encode(in, in_len, _out);
			bytes out(_out, _out + out_len);
			return out;
		}

		static bytes EncodeAsVector(const string& in) {
            byte* _in = reinterpret_cast<byte*>(const_cast<char*>(in.c_str()));
			return EncodeAsVector(_in, in.size());
		}

		static bytes EncodeAsVector(const bytes& in) {
			return EncodeAsVector(in.data(), in.size());
		}

        // Origin DecodeAsString
        static string DecodeAsString(const byte* in, const length& in_len) {
            length out_len = LenDecoded(in, in_len);
			string out(out_len, '\0');
            if (Decode(in, in_len, reinterpret_cast<byte*>(&out[0])))
                return out;
            return "";
        }

        static string DecodeAsString(const string& in) {
            byte* _in = reinterpret_cast<byte*>(const_cast<char*>(in.c_str()));
            return DecodeAsString(_in, in.size());
        }

        static string DecodeAsString(const bytes& in) {
			return DecodeAsString(in.data(), in.size());
        }

		// Origin DecodeAsVector
        static bytes DecodeAsVector(const byte* in, const length& in_len) {
			length out_len = LenDecoded(in, in_len);
            byte* _out = new byte[out_len];
            if (Decode(in, in_len, _out)) {
				bytes out(_out, _out + out_len);
                return out;
            }
            delete[] _out;
            return {};
        }

        static bytes DecodeAsVector(const string& in) {
			byte* _in = reinterpret_cast<byte*>(const_cast<char*>(in.c_str()));
			return DecodeAsVector(_in, in.size());
        }

        static bytes DecodeAsVector(const bytes& in) {
			return DecodeAsVector(in.data(), in.size());
        }

    };

}

#undef length
#undef byte
#undef bytes
#undef string
