# PolyZip
##  (Nothing.. is.. Safe..)

PolyZip is a Python 3 command-line tool that embeds ZIP archives into a wide range of media and document formats—PNG, JPEG, GIF, PDF, BMP, WebP, TIFF, WAV, MP3, FLAC, OGG, AVI, MKV, WebM, FLV, ICO, CUR, ICNS, MP4, MOV, M4A, EXE, DLL, ELF, MSI, TTF, OTF, and WOFF —by leveraging each format's trailing-data tolerance or internal chunk/atom structure. For PNG, it injects the ZIP archive into the first IDAT chunk and corrects central directory offsets; for JPEG/GIF/PDF, it appends ZIP data after the EOI/trailer/EOF markers; for RIFF-based formats (BMP, WebP, WAV, AVI), it appends ZIP data beyond the declared chunk size; for TIFF, MP3, FLAC, OGG, ICO/CUR/ICNS, MP4/MOV/M4A, ELF, MSI, and font formats (TTF/OTF/WOFF), it appends after the last valid header/frame/atom and updates ZIP offsets accordingly. The resulting files display normally in standard viewers yet remain fully valid ZIP archives when renamed to `.zip` or extracted with standard tools.

**🆕 NEW: Enhanced with encrypted hidden chat functionality!** PolyZip 2.1 now includes a sophisticated chat system that creates AES-256 encrypted chat logs hidden within any supported file format. Chat messages are completely invisible to external analysis and protected by military-grade encryption using Argon2id password derivation or secure key files.

Original PNG+ZIP polyglot technique by [DavidBuchanan314](https://github.com/DavidBuchanan314/tweetable-polyglot-png); extended multi-format embedding, multi-file packing, extraction, detection, and encrypted chat implementation by [InfoSecREDD](https://github.com/InfoSecREDD).

## Features

- Create polyglot files from multiple formats:
  - **PNG + ZIP**
  - **JPG + ZIP**
  - **JPEG + ZIP**
  - **GIF + ZIP**
  - **PDF + ZIP**
  - **BMP + ZIP**
  - **WebP + ZIP**
  - **TIFF + ZIP**
  - **WAV + ZIP**
  - **MP3 + ZIP**
  - **FLAC + ZIP**
  - **OGG + ZIP**
  - **AVI + ZIP**
  - **MKV + ZIP**
  - **WebM + ZIP**
  - **FLV + ZIP**
  - **ICO + ZIP**
  - **CUR + ZIP**
  - **ICNS + ZIP**
  - **MP4 + ZIP**
  - **MOV + ZIP**
  - **M4A + ZIP**
  - **EXE + ZIP**
  - **DLL + ZIP**
  - **ELF + ZIP**
  - **MSI + ZIP**
  - **TTF + ZIP**
  - **OTF + ZIP**
  - **WOFF + ZIP**

- **🔒 Encrypted Hidden Chat System**:
  - Create secure chat logs hidden in any supported file format
  - AES-256-GCM encryption with authenticated encryption
  - Argon2id password derivation for maximum security
  - Key file authentication with auto-generation
  - Perfect steganography - files appear completely normal
  - Tamper detection and protection
  - Export to HTML, JSON, or text formats

- Automatic detection of embedded content
- Extract hidden files from polyglot containers
- Support for multiple files in a single container
- Automatic virtual environment management
- Cross-platform compatibility

## Installation

1. Clone the repository:
```bash
git clone https://github.com/InfoSecREDD/PolyZip.git
cd PolyZip
```

2. Make the script executable:
```bash
chmod +x poly.py
```

3. Run the script - it will automatically set up the required environment:
```bash
./poly.py
```

## Usage

### Packing Files

Embed one or more files into a cover file:
```bash
./poly.py pack cover.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|ogg|avi|mkv|webm|flv|ico|cur|icns|mp4|mov|m4a|exe|dll|elf|msi|ttf|otf|woff] file1 [file2 ...] output.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|ogg|avi|mkv|webm|flv|ico|cur|icns|mp4|mov|m4a|exe|dll|elf|msi|ttf|otf|woff]
```

Example:
```bash
./poly.py pack cover.png secret.txt output.png
```

### Extracting Files

Extract hidden files from a polyglot container:
```bash
./poly.py extract input.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|ogg|avi|mkv|webm|flv|ico|cur|icns|mp4|mov|m4a|exe|dll|elf|msi|ttf|otf|woff] [output]
```

If no output directory is specified, files will be extracted to a directory named after the input file.

Example:
```bash
./poly.py extract output.png
```

### Detecting Embedded Content

Scan files for embedded content:
```bash
./poly.py detect [input.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|ogg|avi|mkv|webm|flv|ico|cur|icns|mp4|mov|m4a|exe|dll|elf|msi|ttf|otf|woff]]
```

If no file is specified, it will scan the current directory for all supported files.

Example:
```bash
./poly.py detect
```

### 🔒 Encrypted Hidden Chat System

#### Creating Encrypted Chats

Create a new encrypted chat hidden in any file format:

**With Password Protection:**
```bash
./poly.py chat create cover.[any] output.[any] "Chat Title" --password=yourpassword
```

**With Key File Authentication:**
```bash
./poly.py chat create cover.[any] output.[any] "Chat Title" --key=keyfile.key
```

**Examples:**
```bash
# Create password-protected chat in PNG
./poly.py chat create photo.png secret_chat.png "Team Communications" --password=SecurePass123

# Create key-protected chat in PDF
./poly.py chat create document.pdf secret_chat.pdf "Private Discussion" --key=team.key

# Create unencrypted chat in JPEG
./poly.py chat create image.jpg chat.jpg "Public Chat"

# Works with any file format
./poly.py chat create video.mp4 secret_chat.mp4 "Mission Planning" --password=classified
```

#### Adding Messages

Add messages to existing chats:

```bash
./poly.py chat add chat.[any] "Sender Name" "Message content" [encryption_option]
```

**Examples:**
```bash
# Add to password-protected chat
./poly.py chat add secret_chat.png "Alice" "Hello team!" --password=SecurePass123

# Add to key-protected chat
./poly.py chat add secret_chat.pdf "Bob" "Mission status update" --key=team.key

# Add to unencrypted chat
./poly.py chat add chat.jpg "Charlie" "Public message"
```

#### Reading Chats

Display chat contents:

```bash
./poly.py chat read chat.[any] [--format=terminal|json|html] [encryption_option]
```

**Examples:**
```bash
# Read password-protected chat
./poly.py chat read secret_chat.png --password=SecurePass123

# Read key-protected chat with JSON format
./poly.py chat read secret_chat.pdf --format=json --key=team.key

# Read with HTML format
./poly.py chat read chat.mp4 --format=html
```

#### Exporting Chats

Export chats to files:

```bash
./poly.py chat export chat.[any] output.[txt|json|html] [encryption_option]
```

**Examples:**
```bash
# Export to HTML
./poly.py chat export secret_chat.png backup.html --password=SecurePass123

# Export to JSON
./poly.py chat export secret_chat.pdf backup.json --key=team.key

# Export to text
./poly.py chat export chat.jpg backup.txt
```

### 🔐 Security Features

- **AES-256-GCM Encryption**: Military-grade encryption with authenticated encryption
- **Argon2id Password Derivation**: Secure password hashing resistant to GPU attacks
- **Key File Authentication**: Auto-generated secure keys for file-based authentication
- **Perfect Steganography**: Hidden data is completely undetectable by external analysis
- **Tamper Detection**: GCM authentication prevents modification of encrypted data
- **No Information Leakage**: Even if extracted, encrypted data remains unreadable

**💡 Pro Tip**: Files with hidden chats can be opened normally in any image viewer, PDF reader, or media player. The hidden chat is completely invisible to external tools and analysis.

## Technical Details

Our tool leverages each format's tolerance for extra or embedded data beyond its standard file structure. Most viewers stop reading at defined end markers or fields and ignore trailing bytes, allowing a valid ZIP archive to be appended without affecting normal display.

#### PNG + ZIP
- **Chunk-based format**: PNG files begin with an 8-byte signature, followed by a sequence of chunks (4-byte length, 4-byte type, chunk data, 4-byte CRC). IDAT chunks contain compressed image data; decoders concatenate all IDAT payloads based on declared lengths and verify each chunk's CRC. Any extra bytes beyond a chunk's specified length (including our appended ZIP) are ignored by standard PNG parsers.
- **Embedding approach**: We insert the ZIP archive into the first IDAT chunk after its declared data, update the length and CRC so the image remains valid, and leave IEND untouched. Viewers decode the image normally, while the ZIP central directory offsets point into the embedded data.

#### JPEG + ZIP
- **Marker-based format**: JPEG streams consist of markers (`FF D8` SOI, APPn segments, `FF DA` SOS, compressed scan data, `FF D9` EOI). Parsers stop decoding at the EOI marker and ignore any trailing bytes.
- **Embedding approach**: We split the file at the final `FF D9`, write out the image data, then append the ZIP archive. ZIP offsets are fixed so renaming to `.zip` yields a valid archive, while image viewers ignore the appended data.

#### GIF + ZIP
- **Block-oriented format**: GIF files start with a header (`GIF87a`/`GIF89a`), logical screen descriptor, optional color tables, data blocks, and end with a single trailer byte (`0x3B`).
- **Embedding approach**: We truncate the file at the trailer, append our ZIP archive, and adjust ZIP pointers. GIF viewers stop at `0x3B` and ignore the ZIP data.

#### PDF + ZIP
- **Text-based format**: PDF documents end with a `%%EOF` marker (often followed by a newline). PDF readers scan backwards to locate the last `%%EOF` and ignore any content that follows.
- **Embedding approach**: We write out the PDF up to and including the final `%%EOF`, then append the ZIP archive. PDF viewers load the document normally, while ZIP tools see a playable archive.

#### BMP + ZIP
- **Header-driven format**: BMP files start with 'BM', followed by a 4-byte file size field at offset 2 (little-endian), reserved fields, and a pixel-data offset pointer. Readers rely on the declared file size or pixel-data offset to load image data, ignoring trailing data.
- **Embedding approach**: We append the ZIP archive after the pixel data, then fix ZIP offsets. Standard image loaders read only the declared bytes and dismiss extra content.

#### WebP + ZIP / WAV + ZIP / AVI + ZIP
- **RIFF container**: These formats use a RIFF header (`RIFF`, 4-byte total size, format tag) followed by sub-chunks (e.g., `WEBP`, `WAVE`, `AVI `). Parsers read chunks based on length fields and ignore bytes beyond the container size.
- **Embedding approach**: We append the ZIP archive after the declared RIFF data and update ZIP offsets so the archive remains valid.

#### TIFF + ZIP
- **Tagged format**: TIFF files begin with an endianness marker (`II`/`MM`), magic number 42, and an offset to the first Image File Directory (IFD). Readers traverse IFD pointers and image data strips; trailing bytes are never referenced.
- **Embedding approach**: We append the ZIP archive at the end, then update ZIP offsets. TIFF viewers ignore the extra data.

#### MP3 + ZIP
- **Frame-based format**: MP3 audio is composed of sequential frames, each with a frame sync header (`0xFFF`) and payload. Decoders process frames until no valid header remains; any extra bytes at the end are ignored.
- **Embedding approach**: We append the ZIP archive after the last frame and fix ZIP offsets; audio players play all frames and disregard the ZIP.

#### FLAC + ZIP
- **Block-based format**: FLAC files start with `fLaC`, followed by metadata blocks (ending with the LAST-METADATA-BLOCK flag) and audio frames. Decoders read until the last audio frame and ignore trailing data.
- **Embedding approach**: We append the ZIP archive after the final frame and adjust ZIP offsets.

#### ICO + ZIP / CUR + ZIP
- **Directory-entry format**: Icon/Cursor files begin with an ICONDIR header (entry count) and ICONDIRENTRY array (each with image data offset and size). Readers load images based on these offsets and ignore data beyond.
- **Embedding approach**: We append the ZIP archive after all image entries and fix ZIP offsets.

#### MP4 + ZIP / MOV + ZIP
- **ISO BMFF container**: MP4/MOV files are organized in boxes (4-byte size, 4-byte type, data). Parsers read each box based on its size field and disregard any extra bytes after the final box.
- **Embedding approach**: We append the ZIP archive after the last atom and update ZIP offsets so renaming to `.zip` yields a valid archive.

#### EXE + ZIP / DLL + ZIP
- **PE executable format**: Windows PE files start with an `MZ` DOS stub, followed by a PE header (at `e_lfanew`), section table, and section data blocks. Loaders and PE tools reference section table sizes to map data; trailing bytes beyond the last section are ignored.
- **Embedding approach**: We append the ZIP archive after all declared sections and fix ZIP offsets so the archive remains valid.

#### OGG + ZIP
- **Container format**: OGG files use a bitstream container with pages containing packet data. Each page has a header with capture pattern, stream serial number, and page sequence. Decoders process pages sequentially until no more valid pages remain; trailing bytes are ignored.
- **Embedding approach**: We append the ZIP archive after the last valid OGG page and update ZIP offsets. Audio players decode all valid pages and ignore the appended ZIP data.

#### MKV + ZIP
- **Matroska container**: MKV files use the Extensible Binary Meta Language (EBML) format with elements containing size and data fields. The container has a defined structure with header, segment info, tracks, and clusters. Parsers read elements based on size fields and ignore trailing data.
- **Embedding approach**: We append the ZIP archive after the last cluster element and fix ZIP offsets so the archive remains valid while video players ignore extra bytes.

#### WebM + ZIP
- **Matroska-based format**: WebM is a subset of the Matroska container using VP8/VP9 video and Vorbis/Opus audio. Like MKV, it uses EBML structure with size-defined elements. Decoders stop at the last valid element and ignore trailing bytes.
- **Embedding approach**: We append the ZIP archive after the final cluster and update ZIP offsets. WebM players process only the declared elements and disregard the ZIP data.

#### FLV + ZIP
- **Adobe Flash Video format**: FLV files start with an FLV header (signature, version, flags, header length) followed by tag packets (type, size, timestamp, data). Decoders process tags sequentially based on size fields and ignore any data beyond the last valid tag.
- **Embedding approach**: We append the ZIP archive after the final tag and adjust ZIP offsets. Flash players and compatible decoders ignore the trailing ZIP data.

#### ICNS + ZIP
- **Apple Icon format**: ICNS files begin with a 4-byte type identifier (`icns`), followed by a 4-byte file length, then a series of icon elements (4-byte type, 4-byte length, icon data). Readers process elements based on declared lengths and ignore trailing bytes.
- **Embedding approach**: We append the ZIP archive after all icon elements and fix ZIP offsets so the archive remains valid while icon viewers ignore extra data.

#### M4A + ZIP
- **ISO BMFF container**: M4A files use the same ISO Base Media File Format as MP4, organized in atoms/boxes (4-byte size, 4-byte type, data). Audio players read atoms based on size fields and ignore trailing data beyond the last atom.
- **Embedding approach**: We append the ZIP archive after the final atom and update ZIP offsets. M4A players process only the declared atoms and disregard the ZIP data.

#### ELF + ZIP
- **Linux executable format**: ELF files start with an ELF header containing entry point, program header table offset, section header table offset, and other metadata. Loaders map segments based on program headers and ignore data beyond the declared sections.
- **Embedding approach**: We append the ZIP archive after all section data and fix ZIP offsets so the archive remains valid while ELF loaders ignore trailing bytes.

#### MSI + ZIP
- **Microsoft Installer format**: MSI files are structured storage compound documents with a defined directory structure. Installers read the compound document structure and ignore any trailing data beyond the declared storage size.
- **Embedding approach**: We append the ZIP archive after the compound document structure and update ZIP offsets. MSI installers process only the declared storage content and ignore extra bytes.

#### TTF + ZIP / OTF + ZIP / WOFF + ZIP
- **Font file formats**: TTF/OTF files contain font tables with a table directory specifying offsets and lengths. WOFF adds compression wrapper with declared uncompressed size. Font renderers read tables based on directory entries and ignore trailing data.
- **Embedding approach**: We append the ZIP archive after all font table data and fix ZIP offsets. Font systems load only the declared tables and disregard the ZIP data.

#### 🔒 Encrypted Chat Technical Implementation

The encrypted chat system uses a sophisticated multi-layered approach:

1. **Data Structure**: Chat messages are stored in JSON format with timestamps, participants, and message content
2. **Encryption Layer**: 
   - **AES-256-GCM**: Provides both confidentiality and authentication
   - **Argon2id**: Password-based key derivation resistant to GPU attacks
   - **Random Salt**: Unique salt for each chat prevents rainbow table attacks
   - **Key Files**: Auto-generated 256-bit keys for file-based authentication
3. **Steganographic Embedding**: Encrypted data is embedded using the same techniques as ZIP files
4. **Format Agnostic**: Works with any supported file format (PNG, JPEG, PDF, MP4, etc.)
5. **Tamper Detection**: GCM authentication tag prevents modification without detection

**Security Guarantees**:
- Even if the cover file is extracted, the chat data remains encrypted
- No information leakage about chat contents or participants
- Files appear completely normal to external analysis tools
- Brute force attacks are mitigated by Argon2id's computational cost

### Limitations

1. **Cover File Requirements**:
   - **PNG**:
     - Must compress well to leave space for embedded data
     - Must have at least 257 unique colors if not using a palette (to prevent Twitter from converting to indexed color)
     - Example: A 1000x1000 pixel PNG with 256 colors will be converted to indexed color by Twitter, breaking the polyglot
     - Example: A noisy or complex PNG might not compress well, leaving little space for embedded data
   
   - **JPEG**:
     - Must have a valid EOI (End of Image) marker (0xFFD9)
     - Some JPEGs may have multiple EOI markers - only the last one is used
     - Example: A JPEG with corrupted EOI marker will fail to embed data
   
   - **GIF**:
     - Must have a valid trailer marker (0x3B)
     - Multi-frame GIFs are supported, but data is embedded after the last frame
     - Example: A GIF with corrupted trailer will fail to embed data
   
   - **PDF**:
     - Must have a valid EOF marker (%%EOF)
     - Some PDFs may have multiple EOF markers - only the last one is used
     - Example: A PDF with corrupted EOF marker will fail to embed data

   - **BMP**:
     - Must have a valid file size field at offset 2 (little endian); viewers ignore trailing bytes
     - Example: A malformed BMP size field may prevent the image from loading

   - **WebP**:
     - Must start with "RIFF" and include the "WEBP" chunk within the first 12 bytes; parsers read only declared chunk size
     - Example: Missing or corrupted "WEBP" chunk can break embedding

   - **TIFF**:
     - Must have a valid byte-order marker ("II" or "MM") and correct IFD pointers; viewers ignore trailing data
     - Example: Corrupted IFD pointers may cause the viewer to reject the file

   - **WAV**:
     - Must start with "RIFF" and include the "WAVE" chunk; header chunk size must match file length
     - Example: Incorrect RIFF size can break audio playback

   - **MP3**:
     - Must end with a proper frame sequence; decoders ignore trailing bytes after the last valid frame
     - Example: Frame sync errors will prevent embedding

   - **FLAC**:
     - Must start with the "fLaC" marker; decoders ignore trailing bytes after the last metadata block
     - Example: Missing STREAMINFO block will prevent decoding

   - **AVI**:
     - Must start with "RIFF" and include the "AVI " chunk; chunk size header must be correct
     - Example: Corrupted chunk size will break video playback

   - **ICO**:
     - Must include a valid icon directory and entries; parsers read only declared images
     - Example: Invalid entry headers may prevent the icon from displaying

   - **CUR**:
     - Must include a valid cursor directory and entries; trailing bytes are ignored
     - Example: Incorrect hotspot coordinates can affect cursor positioning

   - **MP4/MOV**:
     - Must include valid ISO BMFF atoms ("ftyp", "moov"); atom size fields must match declared lengths
     - Example: Missing or misplaced "moov" atom will break playback

   - **OGG**:
     - Must have valid OGG page headers with correct capture patterns and checksums
     - Example: Corrupted page headers will prevent audio/video decoding

   - **MKV**:
     - Must include valid EBML header and segment structure; element size fields must be accurate
     - Example: Missing or corrupted EBML header will prevent video playback

   - **WebM**:
     - Must be a valid Matroska subset with VP8/VP9 video and Vorbis/Opus audio codecs
     - Example: Using unsupported codecs may cause playback failures

   - **FLV**:
     - Must have valid FLV header and properly formatted tag structure
     - Example: Incorrect tag sizes will break Flash video playback

   - **ICNS**:
     - Must include valid icon elements with correct type identifiers and sizes
     - Example: Malformed icon elements may prevent macOS from displaying the icon

   - **M4A**:
     - Must follow ISO BMFF structure with valid audio-specific atoms ("mdhd", "stsd")
     - Example: Missing audio track information will prevent playback

   - **ELF**:
     - Must have valid ELF header with correct magic number and architecture information
     - Example: Incorrect architecture or corrupted headers will prevent execution

   - **MSI**:
     - Must be a valid compound document with proper storage structure
     - Example: Corrupted storage directory will prevent installation

   - **TTF/OTF**:
     - Must have valid font table directory and required tables ("cmap", "glyf", "head", "hhea", "hmtx", "loca", "maxp", "name", "post")
     - Example: Missing required tables will prevent font rendering

   - **WOFF**:
     - Must have valid WOFF header with correct signature and table directory
     - Example: Incorrect compression or table checksums will prevent font loading

2. **Size Limitations**:
   - **PNG**:
     - Maximum size depends on the image characteristics and hosting platform
     - For Twitter: Must be under 3MB to avoid JPEG conversion
     - Compressed size must be less than `(width * height) - size_of_embedded_file`
     - Image must have enough space in its IDAT chunks to embed the ZIP data
     - Example: A 2000x2000 PNG with simple content might compress to 500KB, leaving 2.5MB for embedded data
     - Example: A 2000x2000 PNG with complex content might compress to 2.9MB, leaving only 100KB for embedded data
   
   - **JPEG/GIF/PDF**:
     - No strict size limits beyond the file format's maximum size
     - Limited only by the available space after the file's end marker
     - Hosting platforms may impose their own size restrictions
     - Example: A 1MB JPEG can embed up to 2MB of data (if the platform allows 3MB total)
     - Example: A 5MB PDF can embed up to 5MB of data (if the platform allows 10MB total)

   - **BMP**:
     - Limited by the 32-bit file size field (max ~4 GB); can embed up to (file size field) minus header size
     - Example: Embedding near 4 GB may hit format or hosting limits

   - **WebP**:
     - Limited by the 32-bit RIFF chunk size (max ~4 GB); subject to image hosting size restrictions
     - Example: Very large WebP files may be disallowed by some platforms

   - **TIFF**:
     - Limited by 32-bit IFD offsets (max ~4 GB); trailing data supports large payloads
     - Example: Hosting large TIFFs may incur platform-specific size constraints

   - **WAV**:
     - Limited by 32-bit RIFF chunk size (max ~4 GB); decoders ignore trailing bytes
     - Example: Embedding several GB of data in WAV may exceed hosting quotas

   - **MP3**:
     - No strict format size limit; embed until file system or hosting limits are reached
     - Example: Some services re-encode or strip trailing bytes on MP3 uploads

   - **FLAC**:
     - No strict format size limit; embed until file system or hosting limits are reached
     - Example: FLAC uploads may be converted or transcoded by certain platforms

   - **AVI**:
     - Limited by 32-bit RIFF chunk size (max ~4 GB); supports large embedded payloads
     - Example: Video hosting sites may strip trailing bytes when transcoding

   - **ICO/CUR**:
     - Limited by 32-bit directory offsets; can embed up to (file size) minus icon data
     - Example: Many icon hosting services discard non-icon data

   - **MP4/MOV**:
     - Limited by 32-bit atom size fields (max ~4 GB); larger files require extended atoms not commonly supported
     - Example: Embedding >4 GB requires extended format support, which is uncommon in viewers

   - **OGG**:
     - No strict format size limit; limited by available disk space and hosting platform restrictions
     - Example: Large OGG files may be transcoded by streaming services, removing ZIP data

   - **MKV**:
     - Limited by EBML variable-length encoding (practically unlimited for most use cases)
     - Example: Some players may have performance issues with very large files

   - **WebM**:
     - Same as MKV but typically smaller due to web optimization requirements
     - Example: Web browsers may impose stricter size limits for streaming

   - **FLV**:
     - Limited by 32-bit size fields in tags and file header (max ~4 GB)
     - Example: Flash players may not handle files approaching the size limit

   - **ICNS**:
     - Limited by icon element count and size fields; typically small files unsuitable for large payloads
     - Example: Very large ICNS files may be rejected by macOS icon caching

   - **M4A**:
     - Same limitations as MP4/MOV due to shared ISO BMFF structure (max ~4 GB)
     - Example: Audio streaming services often strip trailing data during processing

   - **ELF**:
     - Limited by architecture-specific constraints and section table size limits
     - Example: Some systems may reject executables with unusual sizes or structures

   - **MSI**:
     - Limited by compound document format constraints (max ~4 GB for compatibility)
     - Example: Windows installer may flag very large MSI files as suspicious

   - **TTF/OTF/WOFF**:
     - Limited by font table size fields and system font loading limits
     - Example: Font renderers may reject fonts with unusual file sizes or structures

3. **Image Hosting**:
   - **Works on**:
     - Twitter: PNGs under 3MB, JPEGs under 5MB
     - Imgur: Various size limits depending on account type
     - GitHub: Large file support available
     - Discord: Supports large files
   
   - **May not work on**:
     - Reddit: Re-encodes images, breaking the polyglot
     - Facebook: Re-encodes and strips metadata
     - Instagram: Re-encodes and strips metadata
   
   - **Platform-specific considerations**:
     - Some platforms may strip metadata or re-encode images
     - Example: Twitter's image processing preserves PNG structure but may convert to JPEG if over 3MB
     - Example: Reddit's image processing breaks the polyglot by re-encoding the image

   - **Audio & Video Hosting**:
     - Streaming platforms (YouTube, Vimeo, SoundCloud) often re-encode media, removing trailing ZIP data
     - Use direct file hosting (GitHub Releases, cloud storage) to preserve raw polyglot files
   - **Document Hosting**:
     - PDF attachments in email or file-sharing services typically preserve trailing data
     - Example: Sending a polyglot PDF as an email attachment maintains both viewability and ZIP payload
   
   - **New Format Hosting Considerations**:
     - **OGG/MKV/WebM/FLV**: Video platforms typically transcode these formats, breaking polyglots
     - **M4A**: Audio services may normalize or compress files, stripping trailing data
     - **ICNS**: macOS icon services may process or cache icons, potentially removing ZIP data
     - **ELF**: Linux package repositories may strip or modify executables during processing
     - **MSI**: Software distribution platforms may scan and modify installer files
     - **TTF/OTF/WOFF**: Font hosting services may validate and potentially strip non-font data
     - **Recommendation**: Use direct file hosting or cloud storage for new formats to preserve polyglot integrity

4. **Technical Limitations**:
   - ZIP file offsets must be adjusted to account for the cover file's size
   - Some file formats may have internal size checks that limit embedding
   - Example: A ZIP file with absolute paths may fail if the cover file is too large
   - Example: Some PDF readers may fail to open very large polyglot PDFs
   - **PE Formats (EXE/DLL)**:
     - Some third-party GUI utilities (WinRAR, macOS Archive Utility) may report the archive as corrupted due to trailing data. Windows Explorer's built-in extractor and command-line tools (`unzip`, `7z`) handle it correctly after renaming to `.zip`.

5. **🔒 Chat System Limitations**:
   - **Password Security**: Passwords are only as strong as the user makes them
   - **Key File Security**: Key files must be stored securely and transmitted safely
   - **Platform Processing**: Some platforms may strip or modify files, breaking the hidden chat
   - **File Size**: Large chat histories may exceed platform upload limits
   - **Backup Responsibility**: Users must backup key files and passwords - lost credentials mean lost access

### Dependencies

- Python 3.x
- `cryptography` library (for AES-256-GCM and Argon2id)
- Optional: python-magic (for better file type detection)

## Security Considerations

- The tool creates valid files that can be viewed normally
- **🔒 Encrypted chats are protected by military-grade AES-256-GCM encryption**
- **🔑 Passwords use Argon2id derivation resistant to GPU attacks**
- **🛡️ Key files provide secure file-based authentication**
- **👁️ Hidden data is completely undetectable by external analysis**
- **🔒 Even if extracted, encrypted data remains unreadable without proper credentials**
- Embedded data is not encrypted by default (except for chat system)
- Files can be extracted using standard ZIP tools by renaming the file extension
- Detection tools may flag these files as suspicious
- **⚠️ Users are responsible for securing their passwords and key files**

## Quick Start Examples

### File Hiding (Traditional)
```bash
# Hide files in an image
./poly.py pack photo.png secrets.txt hidden_photo.png

# Extract hidden files
./poly.py extract hidden_photo.png

# Detect hidden data
./poly.py detect hidden_photo.png
```

### 🔒 Encrypted Chat System
```bash
# Create encrypted chat
./poly.py chat create photo.jpg secret_chat.jpg "Team Alpha" --password=SecretMission2024

# Add encrypted messages
./poly.py chat add secret_chat.jpg "Smith" "Package secured" --password=SecretMission2024
./poly.py chat add secret_chat.jpg "Jones" "Extraction complete" --password=SecretMission2024

# Read encrypted chat
./poly.py chat read secret_chat.jpg --password=SecretMission2024

# Export to HTML
./poly.py chat export secret_chat.jpg backup.html --password=SecretMission2024
```

### Multi-Format Support
```bash
# Works with any format
./poly.py chat create document.pdf secret.pdf "Legal Team" --key=legal.key
./poly.py chat create video.mp4 secret.mp4 "Production Team" --password=MovieSecret
./poly.py chat create audio.mp3 secret.mp3 "Music Team" --key=band.key
```

## Credits

- Original PNG polyglot technique by [DavidBuchanan314](https://github.com/DavidBuchanan314/tweetable-polyglot-png)
- Current implementation & new techniques by InfoSecREDD

## License

MIT License - See LICENSE file for details
