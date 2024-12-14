import sys
import argparse
import struct
import operator
import os
import errno
import json
from collections import deque
from typing import Optional, List, Tuple, BinaryIO
from enum import Enum

parser = argparse.ArgumentParser(description="""Tool for working with RPG Maker archives.
Supports RPG Maker XP, VX, VX Ace, and MV formats.""")

parser.add_argument('archive', metavar='ARCHIVE_FILE', nargs='?', 
    help="""Path to RPG Maker archive file. For RPG Maker MV, specify a directory. 
    If omitted, reads from STDIN.""")
parser.add_argument('files', metavar='FILE', nargs='*',
    help="""Files to add when creating an archive (-c mode)""")

mode_group = parser.add_argument_group('modes')
mode_group.add_argument('-l', '--list', dest='mode_list', action='store_true',
    help="""List files in archive (default mode)""")
mode_group.add_argument('-x', '--extract', dest='mode_extract', action='store_true', 
    help="""Extract files from archive""")
mode_group.add_argument('-c', '--create', dest='mode_create', action='store_true',
    help="""Create new archive from files""")

options_group = parser.add_argument_group('options') 
options_group.add_argument('-d', '--dir', dest='outdir', default=None, metavar='DIR',
    help="""Directory to extract to or add files from. For extraction, files will be 
    created under DIR. For creation, file paths in archive will be relative to DIR.""")
options_group.add_argument('-k', '--key', dest='key', default=None, metavar='KEY',
    help="""Encryption key in hexadecimal (default: deadcafe). 
    Setting a key implies RPG Maker XP format unless overridden.""")

version_group = parser.add_argument_group('rpg maker version')
version_group.add_argument('-1', '--rgssadv1', dest='v_xp', action='store_true',
    help="""Use RPG Maker XP format (default when using encryption key)""")
version_group.add_argument('-2', '--rgssadv2', dest='v_vx', action='store_true',
    help="""Use RPG Maker VX format (overrides default key format)""") 
version_group.add_argument('-3', '--rgssadv3', dest='v_vxace', action='store_true',
    help="""Use RPG Maker VX Ace format (default when no key specified)""")
version_group.add_argument('--rpgmv', dest='v_mv', action='store_true',
    help="""Use RPG Maker MV format""")

parser.add_argument('-v', '--verbose', action='store_true',
    help="Show detailed debug information")

parser.add_argument('--exts', dest='encrypted_exts', 
    default='.rpgmvp,.rpgmvm,.rpgmvo,.png_,.m4a_,.ogg_',
    help="""Comma-separated list of encrypted file extensions for RPG Maker MV.
    Default extensions are: .rpgmvp (pictures), .rpgmvm (movies), .rpgmvo (audio),
    .png_ (encrypted PNG), .m4a_ (encrypted M4A), .ogg_ (encrypted OGG)""")

# Add color constants
class Color(Enum):
    HEADER = '\033[95m'    # Purple
    INFO = '\033[94m'      # Blue
    SUCCESS = '\033[92m'   # Green
    WARNING = '\033[93m'   # Yellow
    ERROR = '\033[91m'     # Red
    RESET = '\033[0m'      # Reset
    BOLD = '\033[1m'       # Bold

def color_print(msg, color=Color.INFO):
    eprint(f"{color.value}{msg}{Color.RESET.value}")

def eprint(s):
    sys.stderr.write(s + '\n')

def dump_hex_array(bytes):
	return ' '.join('{:02X}'.format(b) for b in bytes)

def add_to_array(a, pos, val, valDefault):
	if (pos < len(a)):
		a[pos] = val
		return
	for i in range(len(a), pos):
		a.append(valDefault)
	a.append(val)

def to_uint32(val):
	return (val & 0xFFFFFFFF)

def read_uint(source, size=4):
	s = source.read(size) if hasattr(source, 'read') else source
	val, = struct.unpack('<I', (s[0:4] if len(s) >= 4 else (s + struct.pack(b'x' * (4 - len(s))))))
	return val

def list_to_array(l, valDefault):
	a = []
	for i, v in l:
		add_to_array(a, i, v, valDefault)
	return a

class KeyTracker(object):
	def __init__(self, key_start):
		self.key = key_start
	def encrypt_int(self, i):
		return struct.pack('<I', to_uint32(operator.xor(i, self.key)))
	def encrypt_bytes(self, a_bytes):
		return self.decrypt_bytes(a_bytes)
	def decrypt_int(self, fIn):
		return operator.xor(read_uint(fIn), self.key)
	def decrypt_bytes(self, a_bytes):
		bytes_key = struct.pack('<I', self.key)
		return (operator.xor(b, bytes_key[pos % 4]) for (pos, b) in enumerate(a_bytes))

class RGSSArchive(object):
	version = 0
	encoding = 'utf-8'
	def get_keytracker(self, key_start):
		pass
	def get_key(self, fIn):
		pass

	def files(self, fIn, match, action):
		files = []
		t = self.get_keytracker(self.get_key(fIn))
		while True:
			pos = fIn.tell()
			fp = self.get_file(fIn, t)
			if fp is None:
				break
			f, name = fp
			try:
				f.name = name.decode(self.encoding)
			except UnicodeDecodeError:
				eprint('Key: 0x{:08X}, Offset: 0x{:08X}'.format(t.key, pos))
				eprint('File: {}'.format(f))
				eprint(dump_hex_array(name[:99]) + (' ...' if (len(name) > 99) else ''))
				raise
			if match(f):
				action(f)
				files.append(f)
		return files
	def write_files(self, fOut, files_and_paths, t, offset_start):
		pass

	def get_file(self, fIn, tracker):
		pass

	def print(self, fIn, f):
		print(f.name)
		self.pass_next(fIn, f)
	def pass_next(self, fIn, f):
		pass
	def extract_list(self, fIn, files, outdir):
		pass
	def extract_inline(self, fIn, f, outdir):
		pass
	def extract_file(self, fIn, f, outdir):
		color_print(f'Extracting {f.name} ({f.size:,} bytes)...', Color.SUCCESS)
		path = os.path.join(*f.name.split('\\'))
		if outdir is not None:
			path = (outdir + os.sep + path)
		d, name = os.path.split(path)
		try:
			os.makedirs(d, exist_ok=True)
		except OSError as ex:
			eprint(f"Error creating directory {d}: {ex}")
			raise
		with open(path, 'wb') as fExtract:
			self.decrypt_data(fIn, fExtract, f.size, f.key)

	def decrypt_data(self, fIn, fOut, size, k):
		def decrypt(bytes):
			nonlocal k
			bytes_k = struct.pack('<I', to_uint32(k))
			bytes_dec = []
			for (pos, b) in enumerate(bytes):
				bytes_dec.append(operator.xor(b, bytes_k[pos % 4]))
				if ((pos % 4) == 3):
					k = to_uint32((k * 7) + 3)
					bytes_k = struct.pack('<I', k)
			return bytearray(bytes_dec)
		count_bytes = 0
		while count_bytes < size:
			remaining = size - count_bytes
			data = fIn.read(4096 if remaining > 4096 else remaining)
			if data == b'':
				raise Exception('Reached end of file attempting decryption: {} ({} of {})'.format(fIn.name, count_bytes, size))
			data_decrypt = decrypt(data)
			count_bytes = count_bytes + len(data)
			fOut.write(data_decrypt)

	def metadata_bin(self, f, key):
		pass

class RGSSADV1(RGSSArchive):
	version = 1
	key = 0xDEADCAFE
	encoding = 'cp1252'
	def __init__(self, key):
		if key is not None:
			self.key = int(key, 16)
		if args.verbose:
			eprint(f'RGSSADV1 init with key={key}')
			eprint(f'Using {"provided" if key else "default"} key: 0x{self.key:08X}')

	def get_key(self, fIn):
		if args.verbose:
			eprint(f'get_key returning: 0x{self.key:08X}')
		return self.key

	def get_keytracker(self, key_start):
		class KeyTracker_V1(KeyTracker):
			def rotate_key(self, v):
				self.key = to_uint32((7 * self.key) + 3)
				return v
			def __init__(self, key_start):
				self.key = key_start
			def encrypt_int(self, i):
				return self.rotate_key(struct.pack('<I', to_uint32(operator.xor(i, self.key))))
			def decrypt_int(self, fIn):
				return self.rotate_key(operator.xor(read_uint(fIn), self.key))
			def decrypt_bytes(self, a_bytes):
				for b in a_bytes:
					yield self.rotate_key(operator.xor(b, (self.key & 0xFF)))
		return KeyTracker_V1(self.key if (key_start is None) else key_start)

	def write_files(self, fOut, files_and_paths, t, offset_start):
		for (f, p) in files_and_paths:
			fOut.write(self.metadata_bin(f, t))
			with open(p, 'rb') as fIn:
				self.decrypt_data(fIn, fOut, f.size, t.key)

	def get_file(self, fIn, tracker):
		key_start = tracker.key
		if args.verbose:
			eprint(f'Reading file with key: 0x{key_start:08X}')
		length_data = fIn.read(4)
		length = tracker.decrypt_int(length_data)
		if length_data == b'':
			if args.verbose:
				eprint('Reached end of archive')
			return None
		if args.verbose:
			eprint(f'File name length: {length}')
		name_enc = fIn.read(length)
		name = bytearray(tracker.decrypt_bytes(name_enc))
		size = tracker.decrypt_int(fIn)
		offset = fIn.tell()
		if args.verbose:
			eprint(f'Found file at offset 0x{offset:08X}, size: {size}')
		return (ArchiveFile(offset, size, '', tracker.key), name)

	def pass_next(self, fIn, f):
		fIn.seek(f.offset + f.size)
	def extract_inline(self, fIn, f, outdir):
		self.extract_file(fIn, f, outdir)

	def metadata_bin(self, f, t):
		a_name = f.name.encode(self.encoding)
		key_start = t.key
		return (
			t.encrypt_int(len(a_name)) +
			bytearray(t.encrypt_bytes(a_name)) +
			t.encrypt_int(f.size)
		)

class RGSSADV3(RGSSArchive):
	version = 3
	def __init__(self):
		if args.verbose:
			eprint('RGSSADV3 init')
		
	def get_keytracker(self, key_start):
		if args.verbose:
			if key_start is None:
				eprint('Using default key: 57')
			else:
				eprint(f'Using provided key: {key_start}')
		return KeyTracker(57 if (key_start is None) else key_start)

	def write_files(self, fOut, files_and_paths, t, offset_start):
		if ((t.key % 9) != 3):
			raise Exception('Provided key does not match encoding parameters. Dividing the key by 9 must yield a remainder of 3 (key % 9 == 3), but key of 0x{:08X} yields remainder of {}'.format(t.key, (t.key % 9)))
		data_header = struct.pack('<I', int((t.key - 3) / 9))
		fOut.write(data_header)
		pos = offset_start + len(data_header)

		for (f, p) in files_and_paths:
			a = self.metadata_bin(f, t)
			pos = pos + len(a)
		marker_end = t.encrypt_int(0)
		pos = pos + len(marker_end)
		for (f, p) in files_and_paths:
			f.offset = pos
			f.key = 42
			fOut.write(self.metadata_bin(f, t))
			pos = pos + f.size
		fOut.write(marker_end)
		for (f, p) in files_and_paths:
			with open(p, 'rb') as fIn:
				self.decrypt_data(fIn, fOut, f.size, f.key)

	def get_key(self, fIn):
		key = ((read_uint(fIn) * 9) + 3)
		if args.verbose:
			eprint(f'Calculated key from header: 0x{key:08X}')
		return key

	def get_file(self, fIn, tracker):
		if args.verbose:
			eprint(f'Reading file with key: 0x{tracker.key:08X}')
		offset_data = fIn.read(4)
		offset = tracker.decrypt_int(offset_data)
		if offset == 0 or offset_data == b'':
			if args.verbose:
				eprint('Reached end of archive')
			return None
		size = tracker.decrypt_int(fIn)
		key_file = tracker.decrypt_int(fIn)
		length = tracker.decrypt_int(fIn)
		if args.verbose:
			eprint(f'Found file: offset=0x{offset:08X}, size={size}, key=0x{key_file:08X}, name_length={length}')
		name_enc = fIn.read(length)
		name = bytearray(tracker.decrypt_bytes(name_enc))
		return (ArchiveFile(offset, size, '', key_file), name)

	def extract_list(self, fIn, files, outdir):
		for (i, f) in enumerate(sorted(files, key = (lambda f: f.offset))):
			if f.offset > fIn.tell():
				skip_bytes = f.offset - fIn.tell()
				color_print(f'Skip {skip_bytes} bytes to jump to file data at offset 0x{f.offset:08X} for File {i}', Color.WARNING)
			fIn.seek(f.offset)
			self.extract_file(fIn, f, outdir)
	def metadata_bin(self, f, t):
		a_name = f.name.encode(self.encoding)
		a = (
			t.encrypt_int(f.offset) +
			t.encrypt_int(f.size) +
			t.encrypt_int(f.key) +
			t.encrypt_int(len(a_name))
		)
		return a + bytearray(t.encrypt_bytes(a_name))

def key_from_file(path_dir):
	eprint(f'Looking for System.json in: {path_dir}')
	possible_paths = [
		os.path.join(path_dir, 'www', 'data', 'System.json'),
		os.path.join(path_dir, 'data', 'System.json'),
		os.path.join(path_dir, 'System.json')
	]
	
	for path_file in possible_paths:
		eprint(f'Checking path: {path_file}')
		if os.path.exists(path_file):
			color_print(f'Found System.json at: {path_file}', Color.SUCCESS)
			try:
				with open(path_file, 'rb') as fKey:
					data = fKey.read().decode('utf-8')
					o = json.loads(data)
					color_print(f'Loaded JSON successfully', Color.SUCCESS)
					
					has_encrypted_images = o.get('hasEncryptedImages', False)
					has_encrypted_audio = o.get('hasEncryptedAudio', False)
					color_print(f'hasEncryptedImages: {has_encrypted_images}', Color.INFO)
					color_print(f'hasEncryptedAudio: {has_encrypted_audio}', Color.INFO)
					
					if not (has_encrypted_images or has_encrypted_audio):
						color_print(f'Game does not appear to have encrypted files', Color.WARNING)
						return None
					
					if 'encryptionKey' in o:
						key = o['encryptionKey']
						if not key:
							color_print(f'Found System.json but encryption key is empty', Color.WARNING)
							return None
						if len(key) % 2 == 1:
							key = '0' + key
						color_print(f'Using encryption key: {key}', Color.SUCCESS)
						return key
					else:
						color_print(f'System.json does not contain encryptionKey field', Color.WARNING)
						return None
			except (IOError, json.JSONDecodeError) as e:
				color_print(f'Warning: Failed to read {path_file}: {str(e)}', Color.ERROR)
				continue
	
	color_print(f'Warning: Could not find System.json with encryption key in {path_dir}', Color.WARNING)
	return None

class RPGMV(RGSSArchive):
	def __init__(self, key = None, **kwargs):
		color_print(f'RPGMV init with key={key}, kwargs={kwargs}', Color.INFO)
		
		path_key = kwargs.get('path', None)
		if path_key is None:
			self.key = None
		else:
			hex_key = kwargs.get('key', None) if path_key is None else key_from_file(path_key)
			if hex_key is None:
				self.key = None
			else:
				try:
					self.key = bytearray.fromhex(hex_key)
				except ValueError as e:
					eprint(f'Error converting key to hex: {str(e)}')
					self.key = None

	def files(self, paths, match, action):
		if self.key is None:
			eprint('No encryption key found - files may not be encrypted or System.json is missing/invalid')
			return []

		encrypted_exts = set(ext.strip().lower() for ext in args.encrypted_exts.split(','))
		if args.verbose:
			eprint(f"Looking for files with extensions: {', '.join(encrypted_exts)}")
		
		files = []
		t = self.get_keytracker(self.key)
		for path in paths:
			if os.path.isdir(path):
				# Recursively walk directory looking for encrypted files
				for root, _, filenames in os.walk(path):
					for filename in filenames:
						name, ext = os.path.splitext(filename)
						if ext.lower() in encrypted_exts:
							full_path = os.path.join(root, filename)
							try:
								with open(full_path, 'rb') as f:
									header = f.read(16)
									if len(header) == 16:  # Only process files big enough to have a header
										f = ArchiveFile(0, os.path.getsize(full_path), full_path, self.key)
										if match(f):
											action(f)
											files.append(f)
							except IOError as e:
								eprint(f'Warning: Could not read {full_path}: {str(e)}')
			else:
				_, ext = os.path.splitext(path)
				if ext.lower() in encrypted_exts:
					f = ArchiveFile(0, os.path.getsize(path), path, self.key)
					if match(f):
						action(f)
						files.append(f)
		return files
	def extract_inline(self, fIn, f, outdir):
		if args.verbose:
			color_print(f"\nProcessing {f.name} ({f.size:,} bytes)", Color.BOLD)
			
		with open(f.name, 'rb') as fData:
			len_header = 16
			header = fData.read(len_header)
			
			# Read and decrypt first block to detect file type
			
			encrypted_content = fData.read(16)
			decrypted_content = bytearray()
			for pos, b in enumerate(encrypted_content):
				decrypted_content.append(operator.xor(b, self.key[pos % len(self.key)]))
			fData.seek(len_header)
			
			name, ext = os.path.splitext(f.name)
			detected_ext = get_file_extension(bytes(decrypted_content))
			
			if detected_ext:
				out_name = name + detected_ext
				if args.verbose:
					color_print(f"  Detected type: {detected_ext}", Color.SUCCESS)
			elif ext.endswith('_'):
				out_name = f.name[:-1]
				if args.verbose:
					color_print(f"  Removing '_' suffix", Color.INFO)
			else:
				ext_map = {'.rpgmvp': '.png', '.rpgmvm': '.webm', '.rpgmvo': '.ogg'}
				mapped_ext = ext_map.get(ext.lower(), ext)
				out_name = name + mapped_ext
				if args.verbose:
					color_print(f"  Using mapped extension: {mapped_ext}", Color.WARNING)
			
			if args.verbose:
				color_print(f"  Extracting to: {out_name}", Color.SUCCESS)
				
			with open(out_name, 'wb') as fOut:
				self.decrypt_data(fData, fOut, (f.size - len_header), self.key)
	def decrypt_data(self, fIn, fOut, size, k):
		len_key = len(k)
		data = fIn.read(len(k))
		data_decrypt = bytearray()
		for (pos, b) in enumerate(data):
			data_decrypt.append(operator.xor(b, k[pos]))
		fOut.write(data_decrypt)
		fOut.write(fIn.read())

class ArchiveFile(object):
	def __init__(self, offset, size, name, key):
		self.offset = offset
		self.size = size
		self.name = name
		self.key = key
	def __str__(self):
		return 'Offset: 0x{:08X}, Size: {}, Key: 0x{:08X}, Length (of name): {}'.format(self.offset, self.size, self.key, ('N/A' if self.name is None else len(self.name)))

def rgss_read_file(fIn: BinaryIO, 
                   pathIn: Optional[str], 
                   mode_extract: bool, 
                   outdir: Optional[str], 
                   key_decrypt: Optional[str]) -> None:
	color_print("\n=== RGSS Archive Reader ===", Color.HEADER)
	color_print(f"Archive: {pathIn if pathIn else 'STDIN'}")
	color_print(f"Operation: {'Extract' if mode_extract else 'List'}")
	if outdir:
		color_print(f"Output Directory: {outdir}")
	if key_decrypt:
		color_print(f"Decryption Key: 0x{int(key_decrypt,16):08X}")
	color_print("=" * 25 + "\n")

	if not fIn.seekable():
		color_print('Note: Input is not seekable, using buffered wrapper', Color.WARNING)
		class UnseekableWrapper(object):
			def __init__(self, fRead):
				self.pos = 0
				self.fRead = fRead
			def read(self, length):
				data = self.fRead.read(length)
				self.pos = self.pos + len(data)
				return data
			def tell(self):
				return self.pos
			def seek(self, pos):
				assert pos >= self.pos
				count = (pos - self.pos)
				while (count > 0):
					a = self.read(count if (count < 4096) else 4096)
					if a == b'':
						raise Exception(f'Reached end of file (0x{self.tell():08X}) trying to seek to position: 0x{pos:08X}')
					count = (count - len(a))
			def fileno(self):
				return self.fRead.fileno()
		fIn = UnseekableWrapper(fIn)

	try:
		header = fIn.read(7).decode('utf-8')
		if header != 'RGSSAD\0':
			raise ValueError('Not a valid RPG Maker archive file')
			
		version = read_uint(fIn, 1)
		if version not in [1, 2, 3]:
			raise ValueError(f'Unsupported archive version: {version}')
			
	except (IOError, OSError) as e:
		color_print(f"Error reading file: {e}", Color.ERROR)
		sys.exit(1)
	except ValueError as e:
		color_print(f"Error: {e}", Color.ERROR)
		sys.exit(1)

	version_names = {
		1: "RPG Maker XP/VX",
		2: "RPG Maker VX", 
		3: "RPG Maker VX Ace"
	}
	color_print(f"Format: {version_names.get(version, 'Unknown')} (Version {version})", Color.INFO)
	
	rgss = RGSSADV1(key_decrypt) if (version == 1) else RGSSADV3()
	color_print(f"Using {rgss.__class__.__name__} handler\n", Color.INFO)
	
	rgss_read(rgss, fIn, mode_extract, outdir)

def rgss_read_path(pathsIn, mode_extract, outdir, key):
	if args.verbose:
		color_print("\n=== RPG Maker MV Reader ===", Color.HEADER)
		color_print(f"Directory: {pathsIn[0]}")
		color_print(f"Operation: {'Extract' if mode_extract else 'List'}")
		if outdir:
			color_print(f"Output Directory: {outdir}")
		color_print("=" * 25 + "\n")
	
	rgss_read(RPGMV(path=pathsIn[0]), pathsIn, mode_extract, outdir)

def rgss_read(rgss, fIn, mode_extract, outdir):
	def action_inline(a, f_extract, d):
		if f_extract:
			return (lambda f: a.extract_inline(fIn, f, d))
		return (lambda f: a.print(fIn, f))
	try:
		files = rgss.files(fIn, (lambda f: True), action_inline(rgss, mode_extract, outdir))
		if mode_extract:
			rgss.extract_list(fIn, files, outdir)
	except KeyboardInterrupt:
		sys.exit(1)
	except BrokenPipeError:
		return

def rgss_write(fOut, dir_root, file_names, key, version):
	rgss = RGSSADV3() if (version == 3) else RGSSADV1(None)
	t = rgss.get_keytracker(int(key, 16))

	if dir_root:
		if not os.path.exists(dir_root):
			eprint('Non-existent root path: {}'.format(dir_root))
			return
		elif (not os.path.isdir(dir_root)):
			eprint('Root path is not a directory: {}'.format(dir_root))
			return
		dir_root = os.path.normpath(dir_root) + '/'
		if dir_root == './':
			dir_root = None

	to_process = deque((os.path.normpath(p) for p in file_names) if (len(file_names) > 0) 
		else ([dir_root] if dir_root else os.listdir(os.getcwd())))
	files_and_paths = deque([])
	while len(to_process) > 0:
		p = to_process.popleft()
		if os.path.isdir(p):
			for f in os.listdir(p):
				to_process.append(os.path.join(p, f))
		else:
			p_part = p
			if dir_root:
				if not p.startswith(dir_root):
					eprint('Path mismatch with root directory: {} (path: {})'.format(dir_root, p))
					return
				p_part = p[len(dir_root):]
			name = (p_part if os.sep == '\\' else p_part.replace(os.sep, '\\'))
			f = ArchiveFile(0, os.path.getsize(p), name, 0)
			files_and_paths.append((f, p))

	fOut.write('RGSSAD'.encode('utf-8'))
	fOut.write(bytearray([0, rgss.version]))
	pos = 8
	rgss.write_files(fOut, list(files_and_paths), t, pos)

def debug(msg):
	if args.verbose:
		color_print(f"[DEBUG] {msg}", Color.INFO)

def get_file_extension(header_bytes):
	signatures = {
		b'\x89PNG\r\n\x1a\n': '.png',
		b'OggS': '.ogg',
		b'\xFF\xFB': '.mp3',
		b'ID3': '.mp3',
		b'RIFF': '.wav',  # Could also be .avi
		b'\x1aE\xDF\xA3': '.webm',  # EBML header (WebM/Matroska)
		b'ftyp': '.m4a',  # ISO Base Media file (MPEG-4)
		b'\xFF\xF1': '.aac',
	}
	
	for signature, ext in signatures.items():
		if header_bytes.startswith(signature):
			return ext
			
	return None

if __name__ == '__main__':
	args = parser.parse_args()
	outdir = None if args.outdir == '' else args.outdir
	if args.mode_create:
		with (sys.stdout.detach() if args.archive is None else open(args.archive, 'wb')) as fOut:
			rgss_write(fOut, outdir, args.files
				, args.key
				, (3 if args.v_vxace else 2 if args.v_vx else 1 if args.v_xp else (3 if args.key is None else 1)))
	else:
		if outdir is None:
			outdir = next(iter(args.files), None)
			if (outdir is not None) and os.path.exists(outdir) and (not os.path.isdir(outdir)):
				rgss_read_path([args.archive] + args.files, args.mode_extract, None, args.key)

		if (os.path.isdir(args.archive) or args.v_mv):
			rgss_read_path([args.archive] + args.files, args.mode_extract, outdir, args.key)
		else:
			with (sys.stdin.detach() if args.archive is None else open(args.archive, 'rb')) as fIn:
				rgss_read_file(fIn, args.archive, args.mode_extract, outdir, args.key)
