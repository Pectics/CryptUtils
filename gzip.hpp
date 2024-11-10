#pragma once

#include <zlib.h>

namespace Pectics {

	class GZip {
    private:
        static const size_t BUFFER_SIZE = 32768;
	public:
        static bool Compress(const uint8_t* in, const size_t& in_len, uint8_t* out, size_t& out_len) {
            z_stream stream{};
            if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
                return false;
            }

            stream.next_in = const_cast<uint8_t*>(in);
            stream.avail_in = in_len;

            // dynamic buffer
            std::vector<uint8_t> buffer;
            uint8_t* outBuffer = new uint8_t[BUFFER_SIZE];

            do {
                stream.next_out = outBuffer;
                stream.avail_out = sizeof(outBuffer);

                int ret = deflate(&stream, Z_FINISH);
                if (ret == Z_STREAM_ERROR) {
                    deflateEnd(&stream);
                    return false;
                }

                buffer.insert(buffer.end(), outBuffer, outBuffer + (sizeof(outBuffer) - stream.avail_out));
            } while (stream.avail_out == 0);

            deflateEnd(&stream);

            // copy to output
            out_len = buffer.size();
            std::memcpy(out, buffer.data(), out_len);

            delete[] outBuffer;
            return true;
        }

        static bool Decompress(const uint8_t* in, const size_t& in_len, uint8_t* out, size_t& out_len) {
            z_stream stream{};
            if (inflateInit2(&stream, 15 | 16) != Z_OK) {
                return false;
            }

            stream.next_in = const_cast<uint8_t*>(in);
            stream.avail_in = in_len;

            // dynamic buffer
            std::vector<uint8_t> buffer;
            uint8_t* outBuffer = new uint8_t[BUFFER_SIZE];

            do {
                stream.next_out = outBuffer;
                stream.avail_out = sizeof(outBuffer);

                int ret = inflate(&stream, 0);
                if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                    inflateEnd(&stream);
                    return false;
                }

                buffer.insert(buffer.end(), outBuffer, outBuffer + (sizeof(outBuffer) - stream.avail_out));
            } while (stream.avail_out == 0);

            inflateEnd(&stream);

            // copy to output
            out_len = buffer.size();
            std::memcpy(out, buffer.data(), out_len);

            delete[] outBuffer;
            return true;
        }

	};

}
