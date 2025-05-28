# PolyZip
##  (Nothing.. is.. Safe..)

PolyZip is a Python 3 command-line tool that embeds ZIP archives into a wide range of media and document formats—PNG, JPEG, GIF, PDF, BMP, WebP, TIFF, WAV, MP3, FLAC, AVI, ICO, CUR, MP4, MOV, EXE, and DLL —by leveraging each format's trailing-data tolerance or internal chunk/atom structure. For PNG, it injects the ZIP archive into the first IDAT chunk and corrects central directory offsets; for JPEG/GIF/PDF, it appends ZIP data after the EOI/trailer/EOF markers; for RIFF-based formats (BMP, WebP, WAV, AVI), it appends ZIP data beyond the declared chunk size; for TIFF, MP3, FLAC, ICO/CUR, and MP4/MOV, it appends after the last valid header/frame/atom and updates ZIP offsets accordingly. The resulting files display normally in standard viewers yet remain fully valid ZIP archives when renamed to `.zip` or extracted with standard tools.

Original PNG+ZIP polyglot technique by [DavidBuchanan314](https://github.com/DavidBuchanan314/tweetable-polyglot-png); extended multi-format embedding, multi-file packing, extraction, and detection implementation by [InfoSecREDD](https://github.com/InfoSecREDD).

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
  - **AVI + ZIP**
  - **ICO + ZIP**
  - **CUR + ZIP**
  - **MP4 + ZIP**
  - **MOV + ZIP**
  - **EXE + ZIP**
  - **DLL + ZIP**

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
./poly.py pack cover.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|avi|ico|cur|mp4|mov|exe|dll] file1 [file2 ...] output.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|avi|ico|cur|mp4|mov|exe|dll]
```

Example:
```bash
./poly.py pack cover.png secret.txt output.png
```

### Extracting Files

Extract hidden files from a polyglot container:
```bash
./poly.py extract input.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|avi|ico|cur|mp4|mov|exe|dll] [output]
```

If no output directory is specified, files will be extracted to a directory named after the input file.

Example:
```bash
./poly.py extract output.png
```

### Detecting Embedded Content

Scan files for embedded content:
```bash
./poly.py detect [input.[png|jpg|jpeg|gif|pdf|bmp|webp|tiff|tif|wav|mp3|flac|avi|ico|cur|mp4|mov|exe|dll]]
```

If no file is specified, it will scan the current directory for all supported files.

Example:
```bash
./poly.py detect
```

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

4. **Technical Limitations**:
   - ZIP file offsets must be adjusted to account for the cover file's size
   - Some file formats may have internal size checks that limit embedding
   - Example: A ZIP file with absolute paths may fail if the cover file is too large
   - Example: Some PDF readers may fail to open very large polyglot PDFs
   - **PE Formats (EXE/DLL)**:
     - Some third-party GUI utilities (WinRAR, macOS Archive Utility) may report the archive as corrupted due to trailing data. Windows Explorer's built-in extractor and command-line tools (`unzip`, `7z`) handle it correctly after renaming to `.zip`.

### Dependencies

- Python 3.x
- Optional: python-magic (for better file type detection)

## Security Considerations

- The tool creates valid files that can be viewed normally
- Embedded data is not encrypted by default
- Files can be extracted using standard ZIP tools by renaming the file extension
- Detection tools may flag these files as suspicious

## Credits

- Original PNG polyglot technique by [DavidBuchanan314](https://github.com/DavidBuchanan314/tweetable-polyglot-png)
- Current implementation & new techniques by InfoSecREDD

## License

MIT License - See LICENSE file for details
