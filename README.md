# PolyZip

A powerful tool for creating polyglot files that combine image/PDF files with ZIP archives. Based on the work of [DavidBuchanan314](https://github.com/DavidBuchanan314/tweetable-polyglot-png).

## Features

- Create polyglot files from multiple formats:
  - PNG + ZIP
  - JPEG + ZIP
  - GIF + ZIP
  - PDF + ZIP
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
./poly.py pack cover.[png|pdf|jpg|gif] file1 [file2 file3 ...] output.[png|pdf|jpg|gif]
```

Example:
```bash
./poly.py pack cover.png secret.txt output.png
```

### Extracting Files

Extract hidden files from a polyglot container:
```bash
./poly.py extract input.[png|pdf|jpg|gif] [output]
```

If no output directory is specified, files will be extracted to a directory named after the input file.

Example:
```bash
./poly.py extract output.png
```

### Detecting Embedded Content

Scan files for embedded content:
```bash
./poly.py detect [input.[png|pdf|jpg|gif]]
```

If no file is specified, it will scan the current directory for all supported files.

Example:
```bash
./poly.py detect
```

## Technical Details

### Supported File Formats

- **PNG**: Uses IDAT chunk manipulation to embed ZIP data
- **JPEG**: Appends ZIP data after the EOI marker
- **GIF**: Appends ZIP data after the trailer marker
- **PDF**: Appends ZIP data after the EOF marker

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

4. **Technical Limitations**:
   - ZIP file offsets must be adjusted to account for the cover file's size
   - Some file formats may have internal size checks that limit embedding
   - Example: A ZIP file with absolute paths may fail if the cover file is too large
   - Example: Some PDF readers may fail to open very large polyglot PDFs

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
