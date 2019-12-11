Signed Transfer File Update
======================

Intended to package up a number of files for e.g. a firmware update and/or supporting files for a microcontroller. Basically signed tar archive, but simple. 

Each entry has a type (currently set to 1 for regular files), a name up to 95 characters, a sha256 hash and a signature that can be verified with a public key.

Uses sha256 and secp256k1 to hash and then sign files.

Bits borrowed from

* sha256 - [https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto](https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto)
* micro-ecc - [https://github.com/kmackay/micro-ecc](https://github.com/kmackay/micro-ecc)


make_keys
============

Generates a private / public key pair, writes them to files in the current directory, and writes out some C code.

```
make_keys foo
```
-> foo.key (private)
-> foo.pub (public)


archiver
============

This creates an archive. The `key` is specified using the base name. e.g. 'foo' not 'foo.key'
```
archiver <key> <input files ...> <output file>
```
-> output file


verifier
============

This verifies an archive given the public key and an archive file. The `key` is specified using the base name. e.g. 'foo' not 'foo.key'

```
verifier <key> <archive file>
```

File format
============

Starts with the magic "STFU", then the number of files/entries (32 bits). This is more for convienience, and is not secured/signed.

```c
typedef struct {
    char magic[4];  //"STFU" signed transfer firmware update
    uint32_t numFiles;
} FUHeader;
```

Each entry has this header record:

```c
typedef struct {
    uint32_t type;
    uint32_t size;
    char name[92];
} FUFileHeader; //100 bytes
```

Followed by the data for the file/payload, then a footer:

```c
typedef struct {
	uint8_t hash[32]; //sha256 of the header + payload
	uint8_t signature[64]; //secp256k1 signature of the hash
} FUFileFooter; //96 bytes

```

Implmentation Notes
============

It's assumed that a micro can't hold everything in memory to verify it first, and the update will likely be streamed and so will likely be writing/flashing as it goes, saving verification for the end. Ideally the data stored will be in some invalid state until verification of the hash + signature checks out. You'll want to keep a valid image or use a bootloader in case the transfer goes sideways or is corrupt/invalid.

Writing non-firmware files e.g. to an embedded filesystem can also be done, perhaps writing to a temporary file and replacing the original if valid.

Since each entry is self-contained and the whole archive header is unprotected, it's possible that a streamed update fails part way and some previous entries have already been written. Plan for that (maybe holding the final write for the end). You can order the files in the archive to help. It's also possible someone maliciously combines valid entries from preexisting archives. Plan for that (or add something to sign the whole thing).

The name is intended to be meaningful in some way, you may call your firmware "firmware.bin" or something to know its executable code instead of a file, or you can use the type field (by adding support in the archiver). It could have the address to flash to, or that could be embedded in the payload (like a .hex file).
