# Real-time-data-compressor

Compressor that can receive data in real time at modern ethernet speeds (895 Mb/s) and compress it into memory using deduplication and compression.We used Content-Defined Chunking to break the input into chunks, SHA-256 hashes to screen for duplicate chunks, and LZW compression to compress non-duplicate chunks.
