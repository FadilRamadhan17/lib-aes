import os
import base64
from io import BytesIO
from flask import Flask, request, render_template, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename
from file import FileHandler
# Komentar import file.py sementara jika belum ada

app = Flask(__name__)

@app.route('/')
def landing():
    print("Landing page loaded")
    return render_template('landing.html')

@app.route('/explore')
def explore():
    return render_template('explore.html')

@app.route('/aes')
def aes():
    return render_template('aes.html')

class FastAES:
    """
    Implementasi AES cepat tanpa IV, hanya menggunakan plaintext dan key.
    Catatan: Tidak menggunakan IV mengurangi keamanan tapi meningkatkan performa.
    Kunci harus memiliki panjang maksimal 16 byte.
    """
    
    def __init__(self, key=None):
        """
        Inisialisasi dengan key, atau generate key secara otomatis jika tidak disediakan
        Key harus berbentuk bytes dan panjangnya tidak lebih dari 16 byte
        """
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
        """
        Enkripsi plaintext menggunakan AES
        """
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
        """
        Dekripsi ciphertext menggunakan AES
        """
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


def read_uploaded_file(uploaded_file):
    """Baca file yang diunggah dan kembalikan konten, nama file, dan ekstensi"""
    filename = secure_filename(uploaded_file.filename)
    extension = FileHandler.get_file_extension(filename)

    if extension == ".pdf": 
        # Untuk PDF, kita perlu menyimpan ke BytesIO terlebih dahulu
        pdf_stream = BytesIO(uploaded_file.read())
        content = FileHandler.read_pdf(pdf_stream)
    elif extension == ".docx":
        # Untuk DOCX, kita juga perlu BytesIO
        docx_stream = BytesIO(uploaded_file.read())
        content = FileHandler.read_docx(docx_stream)
    else:
        # Untuk file teks biasa
        content = uploaded_file.read().decode('utf-8')

    return content, filename, extension

def detect_and_convert_format(content):
    """Deteksi dan konversi format input (hex atau base64) ke bytes"""
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
        if all(c in '0123456789abcdefABCDEF' for c in content_str):
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

            content, filename, extension = read_uploaded_file(uploaded_file)
            cipher = aes.encrypt(content)
            
            if output_type == 'char':
                cipher_output = base64.b64encode(cipher).decode('utf-8')
            else:
                cipher_output = cipher.hex()

            output_stream = BytesIO()
            output_stream.write(cipher_output.encode('utf-8'))
            output_stream.seek(0)

            download_filename = f"{os.path.splitext(filename)[0]}_encrypted{extension if extension not in ['.pdf', '.docx'] else '.txt'}"

            return send_file(
                output_stream,
                as_attachment=True,
                download_name=download_filename,
                mimetype="application/octet-stream"
            )

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

            content, filename, extension = read_uploaded_file(uploaded_file)
            
            # Coba deteksi format (hex, base64, atau binary)
            ciphertext_bytes, detected_format = detect_and_convert_format(content)
            if not ciphertext_bytes:
                return render_template('error.html', error=f"Format ciphertext tidak valid. Berikan input hex atau base64 yang valid."), 400

            try:
                plaintext = aes.decrypt(ciphertext_bytes)
            except Exception as e:
                return render_template('error.html', error=f"Gagal mendekripsi: {str(e)}"), 400

            output_stream = BytesIO()
            output_stream.write(plaintext)
            output_stream.seek(0)

            download_filename = f"{os.path.splitext(filename)[0]}_decrypted{extension if extension not in ['.pdf', '.docx'] else '.txt'}"

            return send_file(
                output_stream,
                as_attachment=True,
                download_name=download_filename,
                mimetype="application/octet-stream"
            )

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

if __name__ == '__main__':
    print("Starting Flask application...")
    print("Server akan berjalan di: http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
