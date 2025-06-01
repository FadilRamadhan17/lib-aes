import os
import base64
import time
import tempfile
import uuid
from io import BytesIO
from flask import Flask, request, render_template, send_file, session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from file import FileHandler
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key untuk session

# Dictionary untuk menyimpan file sementara
temp_files = {}

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/explore')
def explore():
    return render_template('explore.html')

@app.route('/proses')
def proses():
    return render_template('proses.html')

@app.route('/aes')
def aes():
    return render_template('aes.html')

class FastAES:
    def __init__(self, key=None):
        # Pastikan kunci tidak lebih dari 16 byte
        if key is None:
            # Generate kunci acak
            self.key = os.urandom(16)
        elif isinstance(key, str):
            # Konversi string ke bytes
            key_bytes = key.encode('utf-8')
            if len(key_bytes) > 16:
                raise ValueError("Kunci tidak boleh lebih dari 16 byte")
            # Padding kunci agar tepat 16 byte
            self.key = key_bytes.ljust(16, b'\0')
        else:
            # Jika key sudah berbentuk bytes
            if len(key) > 16:
                raise ValueError("Kunci tidak boleh lebih dari 16 byte")
            # Padding kunci agar tepat 16 byte
            self.key = key.ljust(16, b'\0')
    
    def encrypt(self, plaintext):
        # Konversi plaintext ke bytes jika masih string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Padding plaintext agar panjangnya kelipatan 16 byte (block size AES)
        padding_length = 16 - (len(plaintext) % 16)
        plaintext += bytes([padding_length]) * padding_length
        
        # Menggunakan mode ECB (karena tanpa IV), tidak disarankan untuk data sensitif
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        # Pastikan ciphertext berbentuk bytes
        if not isinstance(ciphertext, bytes):
            raise ValueError("Ciphertext harus berbentuk bytes")
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.ECB(),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = plaintext[-1]
        if padding_length > 16:
            # Invalid padding, return as is
            return plaintext
        
        return plaintext[:-padding_length]


def format_file_size_with_bytes(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.2f} KB ({size_bytes} bytes)"
    else:
        return f"{size_bytes/(1024*1024):.2f} MB ({size_bytes} bytes)"


def read_uploaded_file(uploaded_file):
    filename = secure_filename(uploaded_file.filename)
    extension = FileHandler.get_file_extension(filename)

    if extension == ".pdf": 
        # Untuk PDF, baca sebagai binary untuk preservasi format lengkap
        content = uploaded_file.read()  # Baca langsung sebagai bytes
        content_type = 'binary'
    elif extension == ".docx":
        content = FileHandler.read_docx(uploaded_file)
        content_type = 'text'
    else:
        content = uploaded_file.read().decode('utf-8')
        content_type = 'text'

    return content, filename, extension, content_type


def detect_and_convert_format(content):
    if isinstance(content, bytes):
        try:
            # Coba decode sebagai string
            content_str = content.decode('utf-8', errors='ignore').strip()
        except Exception:
            # Jika gagal decode, kembalikan content sebagai bytes (mungkin sudah binary)
            return content, 'binary'
    else:
        content_str = content.strip()
    
    # Coba deteksi sebagai hex
    try:
        if all(c in '0123456789abcdefABCDEF' for c in content_str) and len(content_str) % 2 == 0:
            return bytes.fromhex(content_str), 'hex'
    except ValueError:
        pass
    
    # Coba deteksi sebagai base64
    try:
        decoded = base64.b64decode(content_str)
        return decoded, 'base64'
    except Exception:
        pass
    
    # Jika konten asli berbentuk bytes, kembalikan sebagai binary
    if isinstance(content, bytes):
        return content, 'binary'
    
    return None, None


@app.route('/download_encrypted_file/<file_id>')
def download_encrypted_file(file_id):
    try:
        if file_id not in temp_files:
            return render_template('error.html', error="File tidak ditemukan atau sudah kadaluarsa."), 404
        
        file_info = temp_files[file_id]
        cipher_output = file_info['content']
        download_filename = file_info['filename']
        
        # Siapkan file untuk download
        output_stream = BytesIO()
        output_stream.write(cipher_output.encode('utf-8'))
        output_stream.seek(0)
        
        # Hapus file dari memori setelah digunakan
        del temp_files[file_id]
        
        return send_file(
            output_stream,
            as_attachment=True,
            download_name=download_filename,
            mimetype="application/octet-stream"
        )
    except Exception as e:
        return render_template('error.html', error=f"Error during file download: {str(e)}"), 500
    

@app.route('/download_decrypted_file/<file_id>')
def download_decrypted_file(file_id):
    try:
        if file_id not in temp_files:
            return render_template('error.html', error="File tidak ditemukan atau sudah kadaluarsa."), 404
        
        file_info = temp_files[file_id]
        plaintext = file_info['content']
        download_filename = file_info['filename']
        original_extension = file_info.get('extension', '')
        
        # Siapkan file untuk download
        output_stream = BytesIO()
        output_stream.write(plaintext)
        output_stream.seek(0)
        
        # Tentukan mimetype berdasarkan ekstensi asli
        if original_extension == '.pdf':
            mimetype = "application/pdf"
        elif original_extension == '.docx':
            mimetype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        else:
            mimetype = "application/octet-stream"
        
        # Hapus file dari memori setelah digunakan
        del temp_files[file_id]
        
        return send_file(
            output_stream,
            as_attachment=True,
            download_name=download_filename,
            mimetype=mimetype
        )
    except Exception as e:
        return render_template('error.html', error=f"Error during file download: {str(e)}"), 500


@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        key = request.form['key'].encode()  # Ubah ke bytes

        # Validasi panjang kunci
        if len(key) > 16:
            return render_template('error.html', error="Panjang kunci tidak boleh lebih dari 16 byte."), 400
        
        input_type = request.form['input_type']
        output_type = request.form['output_type']
        
        try:
            # Inisialisasi AES dengan bytes key
            aes = FastAES(key)
        except ValueError as e:
            return render_template('error.html', error=str(e)), 400

        if input_type == 'file':
            uploaded_file = request.files.get('file_plaintext')
            if not uploaded_file or uploaded_file.filename == '':
                return render_template('error.html', error=f"Tidak ada file yang diunggah."), 400

            content, filename, extension, content_type = read_uploaded_file(uploaded_file)
            
            # Tentukan nama file download berdasarkan ekstensi asli SEBELUM digunakan
            if extension == '.pdf':
                download_filename = f"{os.path.splitext(filename)[0]}_encrypted.enc"
            else:
                download_filename = f"{os.path.splitext(filename)[0]}_encrypted{extension if extension not in ['.pdf', '.docx'] else '.txt'}"
            
            # Mulai pengukuran waktu
            start_time = time.perf_counter()
            
            # Hitung ukuran file asli
            if isinstance(content, bytes):
                original_size = len(content)
            else:
                original_size = len(content.encode('utf-8'))
            original_bytes = original_size
            
            # Enkripsi content (sudah dalam format yang benar - bytes untuk PDF, string untuk lainnya)
            cipher = aes.encrypt(content)
            
            # Hitung waktu enkripsi
            encryption_time = time.perf_counter() - start_time
            
            # Hitung ukuran file setelah enkripsi
            encrypted_size = len(cipher)
            encrypted_bytes = encrypted_size
            
            if output_type == 'char':
                cipher_output = base64.b64encode(cipher).decode('utf-8')
                output_size = len(cipher_output.encode('utf-8'))
                output_bytes = output_size
                format_type = 'Base64'
            else:
                cipher_output = cipher.hex()
                output_size = len(cipher_output.encode('utf-8'))
                output_bytes = output_size
                format_type = 'Hexadecimal'

            # Siapkan informasi untuk template
            encryption_info = {
                'original_size': format_file_size_with_bytes(original_bytes),
                'encrypted_size': format_file_size_with_bytes(encrypted_bytes),
                'output_size': format_file_size_with_bytes(output_bytes),
                'encryption_time': f"{encryption_time:.16f} detik",
                'filename': filename,
                'format_type': format_type
            }

            # Tampilkan kunci tanpa padding
            key_display = key.decode('utf-8', errors='replace').rstrip('\x00')
            
            # Simpan cipher_output dalam temporary storage dengan unique ID
            file_id = str(uuid.uuid4())
            temp_files[file_id] = {
                'content': cipher_output,
                'filename': download_filename,  # Sekarang sudah terdefinisi
                'extension': extension
            }

            # Tampilkan halaman dengan informasi enkripsi terlebih dahulu
            return render_template('aes.html',
                                 input=input_type,
                                 output=output_type,
                                 key=key_display,
                                 encryption_info=encryption_info,
                                 download_file_id=file_id,
                                 download_filename=download_filename,
                                 original_extension=extension,
                                 show_download_button=True)

        elif input_type == 'text':
            plaintext = request.form['plaintext']
            if not plaintext:
                return render_template('error.html', error=f"Tidak ada teks yang dimasukkan."), 400

            cipher = aes.encrypt(plaintext)
            
            if output_type == 'char':
                cipher_output = base64.b64encode(cipher).decode('utf-8')
            else:
                cipher_output = cipher.hex()

            # Tampilkan kunci tanpa padding
            key_display = key.decode('utf-8', errors='replace').rstrip('\x00')
            
            return render_template('aes.html',
                                   input=input_type,
                                   output=output_type,
                                   plaintext=plaintext,
                                   ciphertext=cipher_output,
                                   key=key_display)
        else:
            return render_template('error.html', error=f"Jenis input tidak valid."), 400

    except Exception as e:
        return render_template('error.html', error=f"Error during encryption: {str(e)}"), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        key = request.form['key1'].encode()  # Ubah ke bytes

        # Validasi panjang kunci
        if len(key) > 16:
            return render_template('error.html', error="Panjang kunci tidak boleh lebih dari 16 byte."), 400
        
        input_type = request.form['input_type1']
        
        try:
            # Inisialisasi AES dengan bytes key
            aes = FastAES(key)
        except ValueError as e:
            return render_template('error.html', error=str(e)), 400

        if input_type == 'file':
            uploaded_file = request.files.get('file_ciphertext1')
            if not uploaded_file or uploaded_file.filename == '':
                return render_template('error.html', error=f"Tidak ada file yang diunggah."), 400

            filename = secure_filename(uploaded_file.filename)
            extension = FileHandler.get_file_extension(filename)
            
            content = uploaded_file.read()
            
            # Coba deteksi format (hex, base64, atau binary)
            ciphertext_bytes, detected_format = detect_and_convert_format(content)
            if not ciphertext_bytes:
                return render_template('error.html', error=f"Format ciphertext tidak valid. Berikan input hex atau base64 yang valid."), 400

            # Mulai pengukuran waktu
            start_time = time.perf_counter()

            encrypted_size = len(content)
            encrypted_bytes = encrypted_size

            try:
                plaintext = aes.decrypt(ciphertext_bytes)
            except Exception as e:
                return render_template('error.html', error=f"Gagal mendekripsi: {str(e)}"), 400

            # Hitung waktu dekripsi
            decryption_time = time.perf_counter() - start_time
            
            # Hitung ukuran file setelah dekripsi
            decrypted_size = len(plaintext)
            decrypted_bytes = decrypted_size

            # Siapkan informasi untuk template
            decryption_info = {
                'encrypted_size': format_file_size_with_bytes(encrypted_bytes),
                'decrypted_size': format_file_size_with_bytes(decrypted_bytes),
                'decryption_time': f"{decryption_time:.16f} detik",
                'filename': filename
            }

            # Tampilkan kunci tanpa padding
            key_display = key.decode('utf-8', errors='replace').rstrip('\x00')

            # Tentukan ekstensi file asli dan nama download
            if filename.endswith('_encrypted.enc') or filename.endswith('.enc'):
                # Kemungkinan file PDF yang dienkripsi
                base_name = filename.replace('_encrypted.enc', '').replace('.enc', '')
                download_filename = f"{base_name}_decrypted.pdf"
                original_extension = '.pdf'
            else:
                # File lainnya
                base_name = os.path.splitext(filename)[0]
                if base_name.endswith('_encrypted'):
                    base_name = base_name.replace('_encrypted', '')
                
                # Coba deteksi apakah plaintext adalah PDF berdasarkan header
                if plaintext.startswith(b'%PDF'):
                    download_filename = f"{base_name}_decrypted.pdf"
                    original_extension = '.pdf'
                else:
                    download_filename = f"{base_name}_decrypted{extension if extension not in ['.pdf', '.docx'] else '.txt'}"
                    original_extension = extension if extension not in ['.pdf', '.docx'] else '.txt'

            # Simpan plaintext dalam temporary storage dengan unique ID
            file_id = str(uuid.uuid4())
            temp_files[file_id] = {
                'content': plaintext,
                'filename': download_filename,
                'extension': original_extension
            }
            
            # Tampilkan halaman dengan informasi dekripsi terlebih dahulu
            return render_template('aes.html',
                                input1=input_type,
                                key1=key_display,
                                decryption_info=decryption_info,
                                download_file_id=file_id,
                                download_filename=download_filename,
                                original_extension=original_extension,
                                show_download_button_decrypt=True)

        elif input_type == 'text':
            ciphertext = request.form['text_ciphertext1'].strip()
            
            # Coba deteksi format (hex atau base64)
            ciphertext_bytes, detected_format = detect_and_convert_format(ciphertext)
            if not ciphertext_bytes:
                return render_template('error.html', error=f"Format ciphertext tidak valid. Berikan input hex atau base64 yang valid."), 400

            try:
                plaintext = aes.decrypt(ciphertext_bytes)
            except Exception as e:
                return render_template('error.html', error=f"Gagal mendekripsi: {str(e)}"), 400

            # Tampilkan kunci tanpa padding
            key_display = key.decode('utf-8', errors='replace').rstrip('\x00')

            try:
                # Coba decode plaintext sebagai UTF-8
                plaintext_decoded = plaintext.decode('utf-8')
            except UnicodeDecodeError:
                # Jika tidak bisa di-decode sebagai UTF-8, tampilkan sebagai hex
                plaintext_decoded = plaintext.hex()

            return render_template('aes.html',
                                  input1=input_type,
                                  ciphertext1=ciphertext,
                                  plaintext1=plaintext_decoded,
                                  key1=key_display,
                                  detected_format=detected_format)

        else:
            return render_template('error.html', error=f"Jenis input tidak valid."), 400

    except Exception as e:
        return render_template('error.html', error=f"Error during decryption: {str(e)}"), 500

@app.route('/cleanup_temp_files')
def cleanup_temp_files():
    """Route untuk membersihkan file temporary (optional)"""
    temp_files.clear()
    return "Temporary files cleared", 200


if __name__ == '__main__':
    app.run(debug=True)